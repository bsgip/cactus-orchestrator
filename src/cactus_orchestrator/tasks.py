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
from cactus_orchestrator.crud import select_nonfinalised_runs, update_run_run_status
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.model import RunStatus
from cactus_orchestrator.settings import POD_HARNESS_RUNNER_MANAGEMENT_PORT, RUNNER_POD_URL, CactusOrchestratorSettings

logger = logging.getLogger(__name__)


async def is_idle(now: datetime, url: str, idle_seconds: int) -> bool:
    async with ClientSession(base_url=url, timeout=ClientTimeout(30)) as s:
        details = await RunnerClient.last_interaction(s)

    if (now.timestamp() - details.timestamp.timestamp()) > idle_seconds:
        return True
    return False


def is_maxlive_overtime(now: datetime, created_at: datetime, overtime_seconds: int) -> bool:
    if (now.timestamp() - created_at.timestamp()) > overtime_seconds:
        return True
    return False


async def teardown_idle_teststack(
    session: AsyncSession,
    teardowntask_max_lifetime_seconds: int,
    teardowntask_idle_timeout_seconds: int,
) -> None:
    runs = await select_nonfinalised_runs(session)

    for run in runs:
        now = datetime.now(timezone.utc)
        svc_name, statefulset_name, _, _, pod_fqdn = get_resource_names(run.teststack_id)
        pod_url = RUNNER_POD_URL.format(pod_fqdn=pod_fqdn, pod_port=POD_HARNESS_RUNNER_MANAGEMENT_PORT)

        idle = False
        try:
            idle = await is_idle(now, pod_url, teardowntask_idle_timeout_seconds)
        except Exception as exc:
            logger.warning("Call to cactus-runner last request endpoint failed.")
            logger.debug("Exception", exc_info=exc)

        if idle or is_maxlive_overtime(now, run.created_at, teardowntask_max_lifetime_seconds):
            logger.info(f"(Idle/Overtime Task) Shutting down {svc_name}")
            try:
                await finalise_run(run, pod_url, session, RunStatus.finalised_by_timeout, now)
                await session.commit()
                await teardown_teststack(svc_name=svc_name, statefulset_name=statefulset_name)
            except (ApiException, ClientConnectionError) as exc:
                logger.warning(
                    (
                        f"Failed to teardown idle instance with service name {svc_name} because it "
                        "could not be reached, flagging as terminated..."
                    )
                )
                logger.debug(exc)
                await update_run_run_status(session, run.run_id, run_status=RunStatus.terminated, finalised_at=now)
                await session.commit()

            except Exception as exc:
                logger.warning(f"Failed to teardown idle instance with service name {svc_name}", exc_info=exc)
                continue


def generate_idleteardowntask(
    idleteardowntask_repeat_every_seconds: int,
    idleteardowntask_max_lifetime_seconds: int,
    idleteardowntask_idle_timeout_seconds: int,
) -> Callable[[], Coroutine[Any, Any, None]]:
    @repeat_every(seconds=idleteardowntask_repeat_every_seconds)
    async def idleteardowntask() -> None:
        """Task that monitors live teststacks and triggers teardown based on timeout rules."""
        async with db():
            await teardown_idle_teststack(
                db.session, idleteardowntask_max_lifetime_seconds, idleteardowntask_idle_timeout_seconds
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
