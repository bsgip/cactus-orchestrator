import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, Coroutine, Never

from aiohttp import ClientConnectionError
from cactus_runner.client import ClientSession, ClientTimeout, RunnerClient
from fastapi import FastAPI
from fastapi_async_sqlalchemy import db
from fastapi_utils.tasks import repeat_every
from kubernetes.client.exceptions import ApiException
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.api.run import finalise_run, teardown_teststack
from cactus_orchestrator.crud import (
    ACTIVE_RUN_STATUSES,
    count_playlist_runs,
    select_nonfinalised_runs,
    select_playlist_runs,
    update_run_run_status,
)
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.model import Run, RunStatus
from cactus_orchestrator.settings import CactusOrchestratorSettings

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


async def teardown_idle_teststack(
    session: AsyncSession,
    teardowntask_max_lifetime_seconds: int,
    teardowntask_idle_timeout_seconds: int,
    comms_timeout_seconds: int,
) -> None:
    runs = await select_nonfinalised_runs(session)

    # Track playlist_execution_ids we've already processed
    processed_playlists: set[str] = set()

    for run in runs:
        # Skip if this run is part of a playlist we've already processed
        if run.playlist_execution_id and run.playlist_execution_id in processed_playlists:
            continue

        now = datetime.now(timezone.utc)
        run_resource_names = get_resource_names(run.teststack_id)

        idle = False
        try:
            idle = await is_idle(
                now, run_resource_names.runner_base_url, teardowntask_idle_timeout_seconds, comms_timeout_seconds
            )
        except Exception as exc:
            logger.warning("Call to cactus-runner last request endpoint failed.")
            logger.debug("Exception", exc_info=exc)

        # Apply the max timeout but scaled to the number of tests in the playlist (a little crude)
        if run.playlist_execution_id:
            playlist_count = await count_playlist_runs(session, run.playlist_execution_id)
            effective_max_lifetime = teardowntask_max_lifetime_seconds * playlist_count
        else:
            effective_max_lifetime = teardowntask_max_lifetime_seconds

        if idle or is_maxlive_overtime(now, run.created_at, effective_max_lifetime):
            logger.info(f"(Idle/Overtime Task) Shutting down {run_resource_names.service}")
            if run.playlist_execution_id:
                processed_playlists.add(run.playlist_execution_id)

            try:
                await finalize_teststack_runs(
                    session,
                    run,
                    run_resource_names.runner_base_url,
                    RunStatus.finalised_by_timeout,
                    now,
                    comms_timeout_seconds,
                )
                await session.commit()
                await teardown_teststack(run_resource_names)

            except (ApiException, ClientConnectionError) as exc:
                logger.warning(
                    f"Failed to teardown idle instance with service name {run_resource_names.service} because it "
                    "could not be reached, flagging as terminated...",
                    exc_info=exc,
                )
                await finalize_teststack_runs(
                    session, run, run_resource_names.runner_base_url, RunStatus.terminated, now, comms_timeout_seconds
                )
                await session.commit()

            except Exception as exc:
                logger.warning(
                    f"Failed to teardown idle instance with service name {run_resource_names.service}", exc_info=exc
                )
                continue


def generate_idleteardowntask(
    idleteardowntask_repeat_every_seconds: int,
    idleteardowntask_max_lifetime_seconds: int,
    idleteardowntask_idle_timeout_seconds: int,
    comms_timeout_seconds: int,
) -> Callable[[], Coroutine[Any, Any, None]]:
    @repeat_every(seconds=idleteardowntask_repeat_every_seconds)
    async def idleteardowntask() -> None:
        """Task that monitors live teststacks and triggers teardown based on timeout rules."""
        async with db():
            await teardown_idle_teststack(
                db.session,
                idleteardowntask_max_lifetime_seconds,
                idleteardowntask_idle_timeout_seconds,
                comms_timeout_seconds,
            )

    return idleteardowntask


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
            settings.test_execution_comms_timeout_seconds,
        )
        _task_references.add(asyncio.create_task(idleteardowntask()))

    yield  # type: ignore

    # NOTE: Might be unnecessary, but we gracefully shutdown tasks here.
    for task in _task_references:
        task.cancel()

        try:
            await task  # block until it cancels
        except asyncio.CancelledError:
            pass
