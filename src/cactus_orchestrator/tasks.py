import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Never
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi_utils.tasks import repeat_every
from fastapi_async_sqlalchemy import db
from cactus_runner.client import ClientSession, RunnerClient

from cactus_orchestrator.crud import select_nonfinalised_runs
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.model import FinalisationStatus
from cactus_orchestrator.settings import POD_HARNESS_RUNNER_MANAGEMENT_PORT, RUNNER_POD_URL, main_settings
from cactus_orchestrator.api.run import finalise_run, teardown_teststack


async def is_idle(now: datetime, url: str) -> bool:
    s = ClientSession(url)

    details = await RunnerClient.last_request(s)

    if (now.timestamp() - details.timestamp) > main_settings.teardown_idle_timeout_seconds:
        return True
    return False


def is_maxlive_overtime(now: datetime, created_at: datetime) -> bool:
    if (now.timestamp() - created_at.timestamp()) > main_settings.teardown_idle_timeout_seconds:
        return True
    return False


task_references: set[asyncio.Task] = set()


@repeat_every(seconds=120)
async def teardown_teststack_task() -> None:
    """Task that monitors live teststacks and triggers teardown based on timeout rules."""
    runs = await select_nonfinalised_runs(db.session)
    for run in runs:
        now = datetime.now(timezone.utc)  # check now time per loop
        svc_name, statefulset_name, _, _, pod_fqdn = get_resource_names(run.teststack_id)  # type: ignore
        pod_url = RUNNER_POD_URL.format(pod_fqdn=pod_fqdn, pod_port=POD_HARNESS_RUNNER_MANAGEMENT_PORT)
        if await is_idle(now, pod_url) or is_maxlive_overtime(now, run.created_at):

            # finalise
            await finalise_run(run, pod_url, db.session, FinalisationStatus.by_timeout, now)
            await db.session.commit()

            # teardown
            await teardown_teststack(svc_name=svc_name, statefulset_name=statefulset_name)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[Never]:
    """Lifespan event to start background tasks with fastapi app."""
    task = asyncio.create_task(teardown_teststack_task())

    yield  # type: ignore

    task.cancel()
