import asyncio
import logging
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Never

from cactus_runner.client import ClientSession, ClientTimeout, RunnerClient
from fastapi import FastAPI
from fastapi_async_sqlalchemy import db
from fastapi_utils.tasks import repeat_every
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.api.run import finalise_run
from cactus_orchestrator.crud import (
    ACTIVE_RUN_STATUSES,
    select_nonfinalised_runs,
    select_playlist_runs,
    select_run_for_group,
    update_run_run_status,
)
from cactus_orchestrator.model import Run, RunStatus
from cactus_orchestrator.pod.manager import destroy_pod_resources, ensure_images, fetch_running_pods
from cactus_orchestrator.pod.models import PodResources, PodRoutes
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
                    await finalise_run(sibling, runner_url, session, run_status, finalised_at, comms_timeout_seconds)
    else:  # Single run
        if run_status == RunStatus.terminated:
            await update_run_run_status(session, run.run_id, run_status, finalised_at)
        else:
            await finalise_run(run, runner_url, session, run_status, finalised_at, comms_timeout_seconds)


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


async def destroy_orphaned_pods(session: AsyncSession) -> None:
    """Enumerates all running cactus pods and attempts to kill any whose parent run is missing / inactive"""
    settings = get_current_settings()

    for pod in await fetch_running_pods(settings.podman_socket):
        try:
            run = await select_run_for_group(session, pod.run_group_id, pod.run_id)

            # A pod is orphaned under the following situations:
            #  1) The run is missing
            #  2) The run is NOT in a playlist and is marked as inactive
            #  3) The run IS in a playlist and there are no playlist runs that are active
            is_orphaned_pod = True
            if run is not None:
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
        async with db():
            await destroy_idle_pods(
                db.session,
                idleteardowntask_max_lifetime_seconds,
                idleteardowntask_idle_timeout_seconds,
                comms_timeout_seconds,
            )

            await destroy_orphaned_pods(db.session)

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


_task_references: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(app: FastAPI, settings: CactusOrchestratorSettings) -> AsyncIterator[Never]:
    """Lifespan event to start background tasks with fastapi app."""

    if settings.idleteardowntask_enable:
        logger.info("Starting teardown_teststack_task")
        idleteardowntask = generate_idleteardowntask(
            settings.idleteardowntask_repeat_every_seconds,
            settings.idleteardowntask_max_lifetime_seconds,
            settings.idleteardowntask_idle_timeout_seconds,
            settings.comms_timeout_seconds,
        )
        _task_references.add(asyncio.create_task(idleteardowntask()))

        pulltask = generate_pulltask(settings.pulltask_repeat_every_seconds)
        _task_references.add(asyncio.create_task(pulltask()))

    yield  # type: ignore

    # NOTE: Might be unnecessary, but we gracefully shutdown tasks here.
    for task in _task_references:
        task.cancel()

        try:
            await task  # block until it cancels
        except asyncio.CancelledError:
            pass
