import asyncio
import io
import logging
import re
import unicodedata
import zipfile
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Never

from cactus_runner.client import ClientSession, ClientTimeout, RunnerClient
from envoy.server.manager.time import utc_now
from fastapi import FastAPI
from fastapi_async_sqlalchemy import db
from fastapi_utils.tasks import repeat_every
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, undefer

from cactus_orchestrator.api.run import finalise_run
from cactus_orchestrator.crud import (
    ACTIVE_RUN_STATUSES,
    select_nonfinalised_runs,
    select_playlist_runs,
    select_run_for_group,
    update_run_run_status,
)
from cactus_orchestrator.filestore import save_compliance_finalisation_report, save_run_finalisation, save_run_report
from cactus_orchestrator.model import (
    ComplianceRecord,
    ComplianceRequestFinalisation,
    Run,
    RunGroup,
    RunStatus,
    User,
)
from cactus_orchestrator.pod.manager import destroy_pod_resources, ensure_images, fetch_running_pods
from cactus_orchestrator.pod.models import PodResources, PodRoutes, RunningPod
from cactus_orchestrator.settings import CactusOrchestratorSettings, get_current_settings

logger = logging.getLogger(__name__)


async def is_idle(now: datetime, url: str, idle_seconds: int, comms_timeout_seconds: int) -> bool:
    async with ClientSession(base_url=url, timeout=ClientTimeout(comms_timeout_seconds)) as s:
        details = await RunnerClient.last_interaction(s)

    if (now.timestamp() - details.timestamp.timestamp()) > idle_seconds:
        return True
    return False


def is_maxlive_overtime(now: datetime, created_at: datetime, overtime_seconds: int) -> bool:
    if (now.timestamp() - created_at.timestamp()) > overtime_seconds:
        return True
    return False


async def finalize_teststack_runs(
    settings: CactusOrchestratorSettings,
    session: AsyncSession,
    run: Run,
    runner_url: str,
    run_status: RunStatus,
    finalised_at: datetime,
    comms_timeout_seconds: int,
) -> None:
    """Finalize all runs for a teststack (handles both single runs and playlists)."""
    if run.playlist_execution_id:
        playlist_runs = await select_playlist_runs(session, run.playlist_execution_id)
        for sibling in playlist_runs:
            if sibling.run_status in ACTIVE_RUN_STATUSES:
                if run_status == RunStatus.terminated:
                    await update_run_run_status(session, sibling.run_id, run_status, finalised_at)
                else:
                    await finalise_run(
                        settings, sibling, runner_url, session, run_status, finalised_at, comms_timeout_seconds
                    )
    else:  # Single run
        if run_status == RunStatus.terminated:
            await update_run_run_status(session, run.run_id, run_status, finalised_at)
        else:
            await finalise_run(settings, run, runner_url, session, run_status, finalised_at, comms_timeout_seconds)


async def destroy_idle_pods(
    session: AsyncSession,
    max_lifetime_seconds: int,
    idle_timeout_seconds: int,
    comms_timeout_seconds: int,
) -> None:
    """Enumerates runs - tries to find those that are idle / too old. Those runs will be finalised and have their pods
    shutdown."""
    settings = get_current_settings()
    runs = await select_nonfinalised_runs(session)

    # Track playlist_execution_ids we've already processed
    processed_playlists: set[str] = set()

    for run in runs:
        # Skip if this run is part of a playlist we've already processed
        if run.playlist_execution_id and run.playlist_execution_id in processed_playlists:
            continue

        now = datetime.now(UTC)
        pod_resources = PodResources.from_run(settings.podman_network, run)
        pod_routes = PodRoutes.from_run(
            settings.cactus_fqdn,
            settings.envoy_prefix,
            settings.podman_runner_port,
            pod_resources,
            run.run_group,
            run,
            dev_localhost_port_base=settings.dev_runner_localhost_port_base,
        )

        idle = False
        try:
            idle = await is_idle(now, pod_routes.internal_base_url, idle_timeout_seconds, comms_timeout_seconds)
        except Exception as exc:
            logger.warning("Call to cactus-runner last request endpoint failed.")
            logger.debug("Exception", exc_info=exc)

        if idle or is_maxlive_overtime(now, run.created_at, max_lifetime_seconds):
            logger.info(f"(Idle/Overtime Task) Shutting down {run.run_id} at pod {pod_resources.pod_name}")
            if run.playlist_execution_id:
                processed_playlists.add(run.playlist_execution_id)

            try:
                await finalize_teststack_runs(
                    settings,
                    session,
                    run,
                    pod_routes.internal_base_url,
                    RunStatus.finalised_by_timeout,
                    now,
                    comms_timeout_seconds,
                )
                await session.commit()
            except Exception as exc:
                logger.warning(
                    f"Failed to finalize idle instance {run.run_id} at pod {pod_resources.pod_name}: {exc}",
                    exc_info=exc,
                )
            await destroy_pod_resources(settings.podman_socket, pod_resources)


async def terminate_dead_pod_runs(
    session: AsyncSession, running_pods: list[RunningPod], comms_timeout_seconds: int
) -> None:
    """Checks active runs and terminates any whose pod has disappeared or died out-of-band"""
    settings = get_current_settings()
    running_pods_by_name = {pod.name: pod for pod in running_pods}

    runs = await select_nonfinalised_runs(session)

    # Track playlist_execution_ids we've already processed
    processed_playlists: set[str] = set()

    for run in runs:
        if run.playlist_execution_id and run.playlist_execution_id in processed_playlists:
            continue

        if run.pod_name is None:
            # Pod hasn't been created yet (still provisioning) - nothing to reconcile
            continue

        pod = running_pods_by_name.get(run.pod_name)
        if pod is not None and pod.is_running:
            continue

        logger.info(f"(Dead Pod Task) Run {run.run_id} at pod {run.pod_name} has died and will be terminated.")
        if run.playlist_execution_id:
            processed_playlists.add(run.playlist_execution_id)

        now = datetime.now(UTC)
        pod_resources = PodResources.from_run(settings.podman_network, run)
        try:
            await finalize_teststack_runs(settings, session, run, "", RunStatus.terminated, now, comms_timeout_seconds)
            await session.commit()
        except Exception as exc:
            logger.warning(
                f"Failed to terminate dead-pod run {run.run_id} at pod {run.pod_name}: {exc}",
                exc_info=exc,
            )
        await destroy_pod_resources(settings.podman_socket, pod_resources)


async def destroy_orphaned_pods(session: AsyncSession, running_pods: list[RunningPod]) -> None:
    """Enumerates all running cactus pods and attempts to kill any whose parent run is missing / inactive"""
    settings = get_current_settings()

    for pod in running_pods:
        try:
            run = await select_run_for_group(session, pod.run_group_id, pod.run_id)

            # A pod is orphaned under the following situations:
            #  1) The run is missing
            #  2) The run is NOT in a playlist and is marked as inactive
            #  3) The run IS in a playlist and there are no playlist runs that are active
            if run is None:
                # Remember that the run record is held in a transaction UNTIL the job is full spawned
                # This will mean that from this part of the code - it will be appear as missing (record is dirty)
                # we could look for "dirty" DB records but it's easier to just give a startup grace period
                is_orphaned_pod = (
                    utc_now() - pod.created_time
                ).total_seconds() > settings.idleteardowntask_startup_grace_seconds
            else:
                if run.playlist_execution_id:
                    # We can only nuke a playlist pod when ALL playlist runs are inactive
                    playlist_runs = await select_playlist_runs(session, run.playlist_execution_id)
                    is_orphaned_pod = not any(
                        [playlist_run.run_status in ACTIVE_RUN_STATUSES for playlist_run in playlist_runs]
                    )
                else:
                    is_orphaned_pod = run.run_status not in ACTIVE_RUN_STATUSES

            if is_orphaned_pod:
                logger.info(
                    f"(Orphan Task) pod {pod.name} originally for run {pod.run_id} is an orphan and will be removed."
                )
                await destroy_pod_resources(settings.podman_socket, pod.resources)
        except Exception as exc:
            logger.warning(f"Failed to check pod {pod.name} as being orphaned: {exc}", exc_info=exc)


def generate_idleteardowntask(
    idleteardowntask_repeat_every_seconds: int,
    idleteardowntask_max_lifetime_seconds: int,
    idleteardowntask_idle_timeout_seconds: int,
    comms_timeout_seconds: int,
) -> Callable[[], Coroutine[Any, Any, None]]:
    @repeat_every(seconds=idleteardowntask_repeat_every_seconds)
    async def idleteardowntask() -> None:
        """Task that monitors live pods and triggers teardown based on timeout rules."""
        settings = get_current_settings()
        async with db():
            await destroy_idle_pods(
                db.session,
                idleteardowntask_max_lifetime_seconds,
                idleteardowntask_idle_timeout_seconds,
                comms_timeout_seconds,
            )

            running_pods = await fetch_running_pods(settings.podman_socket)
            await terminate_dead_pod_runs(db.session, running_pods, comms_timeout_seconds)
            await destroy_orphaned_pods(db.session, running_pods)

    return idleteardowntask


def generate_pulltask(pulltask_repeat_every_seconds: int) -> Callable[[], Coroutine[Any, Any, None]]:
    @repeat_every(seconds=pulltask_repeat_every_seconds)
    async def pulltask() -> None:
        """Task ensures podman images are always up to date"""
        settings = get_current_settings()
        for version, pod_images in settings.images.items():
            try:
                await ensure_images(settings.podman_socket, pod_images)
            except Exception as exc:
                logger.error(f"Failure to pull {version} images: {exc}", exc_info=exc)

    return pulltask


def safe_filename(name: str, max_length: int = 255, replacement: str = "_") -> str:
    # Normalize unicode so accented chars decompose (é -> e + combining accent)
    name = unicodedata.normalize("NFKD", name)
    name = name.encode("ascii", "ignore").decode("ascii")  # drop non-ascii remnants

    # Whitelist: only allow A-Z a-z 0-9 and hyphen; everything else -> underscore
    name = re.sub(r"[^A-Za-z0-9\-]", replacement, name)

    # Collapse repeated underscores
    name = re.sub(r"_+", "_", name)

    # Strip leading/trailing underscores and hyphens
    name = name.strip("_-")

    # Fallback if everything got stripped out
    if not name:
        name = "unnamed"

    # Truncate to max_length
    name = name[:max_length]

    return name


def remove_first_matching_file(zip_bytes: bytes, suffix: str) -> tuple[bytes, bytes | None]:
    """
    Remove the first file in a ZIP archive whose filename ends with `suffix`.

    Args:
        zip_bytes: The original ZIP archive as bytes.
        suffix: Filename suffix to match against (e.g. ".txt").

    Returns:
        A tuple of:
            - The re-encoded ZIP archive as bytes, with the matched file removed
              (identical to the input if no match was found).
            - The bytes of the removed file, or None if no file matched.
    """
    removed_bytes: bytes | None = None
    removed_name: str | None = None

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as src_zip:
        # Find the first matching entry (by name), preserving original order.
        for info in src_zip.infolist():
            if info.filename.endswith(suffix):
                removed_name = info.filename
                removed_bytes = src_zip.read(info.filename)
                break

        out_buffer = io.BytesIO()
        with zipfile.ZipFile(out_buffer, "w", compression=zipfile.ZIP_DEFLATED) as dst_zip:
            for info in src_zip.infolist():
                if info.filename == removed_name:
                    continue
                dst_zip.writestr(info, src_zip.read(info.filename))

    return out_buffer.getvalue(), removed_bytes


async def migrate_compliance_finalisation() -> None:
    settings = get_current_settings()

    logger.info(
        f"Starting migrate_compliance_finalisation task - records to migrate into {settings.file_store_path.absolute()}"
    )

    while True:
        try:
            async with db():
                session: AsyncSession = db.session
                record = (
                    await session.execute(
                        select(ComplianceRequestFinalisation)
                        .where(ComplianceRequestFinalisation.file_data_migrated.is_(False))
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if record is None:
                    break

                # If there is no file data - nothing to migrate, move on
                if not record.file_data:
                    record.file_data_migrated_error = None
                else:
                    try:
                        save_compliance_finalisation_report(
                            settings.file_store_path,
                            record.compliance_request_finalisation_id,
                            record.file_data,
                        )
                        record.file_data_migrated_error = None
                    except Exception as exc:
                        record.file_data_migrated_error = str(exc)
                record.file_data_migrated = True
                await session.commit()

        except Exception as exc:
            logger.error("Failure migrating compliance finalisation - adding a delay", exc_info=exc)
            await asyncio.sleep(1)
    logger.info("Stopping migrate_run_compliance task")


async def migrate_run_artifact() -> None:
    settings = get_current_settings()

    # Get a count so we can estimate progress
    async with db():
        session: AsyncSession = db.session
        expected_count = (
            await session.execute(
                select(func.count()).select_from(Run).where(Run.run_artifact_migrated.is_(False)).limit(1)
            )
        ).scalar_one()
    logger.info(
        f"Starting migrate_run_artifact task - {expected_count} records"
        + f"to migrate into {settings.file_store_path.absolute()}"
    )

    migrated_count = 0
    while True:
        try:
            async with db():
                session: AsyncSession = db.session
                run = (
                    await session.execute(
                        select(Run)
                        .where(Run.run_artifact_migrated.is_(False))
                        .options(selectinload(Run.run_artifact))
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if run is None:
                    break

                # If there is no run artifact - nothing to migrate, move on
                if run.run_artifact_id is None:
                    run.run_artifact_migrated_error = None
                else:
                    try:
                        archive_bytes, pdf_bytes = remove_first_matching_file(run.run_artifact.file_data, ".pdf")
                        save_run_finalisation(settings.file_store_path, run.run_id, archive_bytes)
                        if pdf_bytes is not None:
                            save_run_report(settings.file_store_path, run.run_id, pdf_bytes)
                        run.run_artifact_migrated_error = None
                    except Exception as exc:
                        run.run_artifact_migrated_error = str(exc)

                migrated_count = migrated_count + 1
                run.run_artifact_migrated = True
                await session.commit()

                if expected_count and (migrated_count % 500) == 0:
                    logger.info(
                        f"migrate_run_artifact: migrated {migrated_count} / {expected_count}"
                        + f" ({100 * migrated_count / expected_count:.02}%) "
                    )

        except Exception as exc:
            logger.error("Failure migrating run - adding a delay", exc_info=exc)
            await asyncio.sleep(1)
    logger.info("Stopping migrate_run_artifact task")


async def migrate_old_compliance_record() -> None:
    """TODO: Delete this after migration completed"""
    settings = get_current_settings()
    base_dir = settings.file_store_path / "deprecated-compliance-records"
    base_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Starting migrate_old_compliance_record task - records to migrate into {base_dir.absolute()}")
    while True:
        try:
            async with db():
                session: AsyncSession = db.session
                db_record = (
                    (
                        await session.execute(
                            select(ComplianceRecord, RunGroup.name, User.user_name)
                            .join(RunGroup, onclause=ComplianceRecord.run_group_id == RunGroup.run_group_id)
                            .join(User, onclause=ComplianceRecord.requester_id == User.user_id)
                            .where(ComplianceRecord.file_data_migrated.is_(False))
                            .options(undefer(ComplianceRecord.file_data))
                            .limit(1)
                        )
                    )
                    .tuples()
                    .one_or_none()
                )
                if db_record is None:
                    break
                record, run_group_name, user_name = db_record

                # Try and migrate to a subdirectory
                try:
                    file_path = base_dir / (
                        safe_filename(f"{user_name}_{run_group_name}_{record.compliance_record_id}") + ".pdf"
                    )

                    with open(file_path, "wb") as fp:
                        fp.write(record.file_data)

                except Exception as exc:
                    record.file_data_migrated_error = str(exc)
                record.file_data_migrated = True
                await session.commit()

        except Exception as exc:
            logger.error("Failure migrating old compliance - adding a delay", exc_info=exc)
            await asyncio.sleep(1)
    logger.info("Stopping migrate_old_compliance_record task")


@asynccontextmanager
async def lifespan(app: FastAPI, settings: CactusOrchestratorSettings) -> AsyncIterator[Never]:
    """Lifespan event to start background tasks with fastapi app."""

    task_references: set[asyncio.Task] = set()

    if settings.idleteardowntask_enable:
        logger.info("Starting teardown_teststack_task")
        idleteardowntask = generate_idleteardowntask(
            settings.idleteardowntask_repeat_every_seconds,
            settings.idleteardowntask_max_lifetime_seconds,
            settings.idleteardowntask_idle_timeout_seconds,
            settings.comms_timeout_seconds,
        )
        task_references.add(asyncio.create_task(idleteardowntask()))

        pulltask = generate_pulltask(settings.pulltask_repeat_every_seconds)
        task_references.add(asyncio.create_task(pulltask()))

        # Temporary migrations
        task_references.add(asyncio.create_task(migrate_old_compliance_record()))
        task_references.add(asyncio.create_task(migrate_compliance_finalisation()))
        task_references.add(asyncio.create_task(migrate_run_artifact()))

    yield  # type: ignore

    # NOTE: Might be unnecessary, but we gracefully shutdown tasks here.
    for task in task_references:
        task.cancel()

        try:
            await task  # block until it cancels
        except asyncio.CancelledError:
            pass
        except Exception:
            # If one task raises an exception - don't block the shutdown of other tasks
            logger.exception(f"Unhandled exception shutting down background task {task.get_name()}")
