import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from typing import AsyncIterator, Never
import os

from cactus_runner.client import ClientSession, RunnerClient
from fastapi import FastAPI
from fastapi_async_sqlalchemy import db
from fastapi_utils.tasks import repeat_every

from cactus_orchestrator.api.run import finalise_run, teardown_teststack
from cactus_orchestrator.crud import select_nonfinalised_runs
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.model import FinalisationStatus
from cactus_orchestrator.settings import POD_HARNESS_RUNNER_MANAGEMENT_PORT, RUNNER_POD_URL, main_settings


logger = logging.getLogger(__name__)


try:
    TEARDOWN_TASK_REPEAT_EVERY_SECONDS = int(os.getenv("TEARDOWN_TASK_REPEAT_EVERY_SECONDS", 120))
except ValueError:
    TEARDOWN_TASK_REPEAT_EVERY_SECONDS = 120


async def is_idle(now: datetime, url: str) -> bool:
    s = ClientSession(url)

    details = await RunnerClient.last_request(s)

    if (now.timestamp() - details.timestamp) > main_settings.teardown_idle_timeout_seconds:
        return True
    return False


def is_maxlive_overtime(now: datetime, created_at: datetime) -> bool:
    if (now.timestamp() - created_at.timestamp()) > main_settings.teardown_max_lifetime_seconds:
        return True
    return False


task_references: set[asyncio.Task] = set()


@repeat_every(seconds=TEARDOWN_TASK_REPEAT_EVERY_SECONDS)
async def teardown_teststack_task() -> None:
    """Task that monitors live teststacks and triggers teardown based on timeout rules."""
    logger.info("running..")
    runs = await select_nonfinalised_runs(db.session)
    for run in runs:
        now = datetime.now(timezone.utc)  # check now time per loop
        svc_name, statefulset_name, _, _, pod_fqdn = get_resource_names(run.teststack_id)  # type: ignore
        pod_url = RUNNER_POD_URL.format(pod_fqdn=pod_fqdn, pod_port=POD_HARNESS_RUNNER_MANAGEMENT_PORT)
        if await is_idle(now, pod_url) or is_maxlive_overtime(now, run.created_at):

            logger.info(f"(Idle/Overtime Task) Shutting down {svc_name}")
            # finalise
            await finalise_run(run, pod_url, db.session, FinalisationStatus.by_timeout, now)
            await db.session.commit()

            # teardown
            await teardown_teststack(svc_name=svc_name, statefulset_name=statefulset_name)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[Never]:
    """Lifespan event to start background tasks with fastapi app."""
    logger.info("Starting teardown_teststack_task")
    await teardown_teststack_task()

    yield  # type: ignore
