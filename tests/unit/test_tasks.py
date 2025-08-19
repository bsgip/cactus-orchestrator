import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Generator
from unittest.mock import AsyncMock, Mock, patch

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fixtures.postgres import generate_async_session
from cactus_runner.client import ClientInteraction
from cactus_runner.models import ClientInteractionType
from sqlalchemy import select

from cactus_orchestrator.model import Run, RunStatus
from cactus_orchestrator.tasks import generate_idleteardowntask


@dataclass
class MockedK8s:
    delete_service: Mock
    delete_statefulset: Mock
    remove_ingress_rule: Mock

    # RunnerClient
    last_interaction: Mock


@pytest.fixture
def k8s_mock() -> Generator[MockedK8s, None, None]:
    with (
        patch("cactus_orchestrator.api.run.delete_service") as delete_service,
        patch("cactus_orchestrator.api.run.delete_statefulset") as delete_statefulset,
        patch("cactus_orchestrator.api.run.remove_ingress_rule") as remove_ingress_rule,
        patch("cactus_orchestrator.api.run.RunnerClient.last_interaction") as last_interaction,
    ):
        yield MockedK8s(
            delete_service=delete_service,
            delete_statefulset=delete_statefulset,
            remove_ingress_rule=remove_ingress_rule,
            last_interaction=last_interaction,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("idle", "created_at", "expect_teardown"),
    [
        (True, datetime.now(tz=timezone.utc), True),  # idle timeout,
        (False, datetime(2025, 1, 1, tzinfo=timezone.utc), True),  # max lifetime
        (False, datetime.now(tz=timezone.utc), False),
    ],
)
@patch("cactus_orchestrator.crud.select_nonfinalised_runs", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.is_idle", spec=AsyncMock)
@patch("cactus_orchestrator.api.run.teardown_teststack", spec=AsyncMock)
@patch("cactus_orchestrator.api.run.finalise_run", spec=AsyncMock)
async def test_teardown_teststack_task(
    mock_finalise_run,
    mock_teardown_teststack,
    mock_is_idle,
    mock_select_nonfinalised_runs,
    idle,
    created_at,
    expect_teardown,
):
    """Test that teardown_teststack_task properly handles non-finalized runs."""

    # Arrange
    mock_runs = [
        Run(
            run_id=1,
            run_group_id=1,
            teststack_id="abc",
            testprocedure_id="ALL_01",
            created_at=created_at,
            finalised_at=None,
            run_status=RunStatus.initialised,
        )
    ]
    mock_is_idle.return_value = idle
    mock_select_nonfinalised_runs.return_value = mock_runs

    # Act
    await generate_idleteardowntask(1, 1, 1)()

    # Assert
    if expect_teardown:
        mock_teardown_teststack.assert_awaited_once()
        mock_finalise_run.assert_awaited_once()
    else:
        mock_teardown_teststack.assert_not_awaited()
        mock_finalise_run.assert_not_awaited()


@pytest.mark.idleteardowntask_enable(1)
@pytest.mark.asyncio
async def test_teardown_idle_teststack(k8s_mock, pg_base_config, client):
    """Ensure background task triggers actions, with DB unmocked."""

    # In the test DB runs 1,5,6 and 8 are all from "2024" and due for max life teardown
    expected_finalised_run_ids = [1, 5, 6, 8]

    # Even if they are still active - still shut them down
    k8s_mock.last_interaction.return_value = ClientInteraction(ClientInteractionType.PROXIED_REQUEST, datetime.now())

    # Let the background task run
    await asyncio.sleep(3)

    # check the DB
    async with generate_async_session(pg_base_config) as session:
        finalised_runs = (
            (await session.execute(select(Run).where(Run.run_id.in_(expected_finalised_run_ids)))).scalars().all()
        )
        for r in finalised_runs:
            assert r.run_status == RunStatus.finalised_by_timeout
            assert_nowish(r.finalised_at)

    # Check we cleared up k8's
    Mock.call_count
    assert k8s_mock.last_interaction.call_count == len(expected_finalised_run_ids)
    assert k8s_mock.delete_service.call_count == len(expected_finalised_run_ids)
    assert k8s_mock.delete_statefulset.call_count == len(expected_finalised_run_ids)
    assert k8s_mock.remove_ingress_rule.call_count == len(expected_finalised_run_ids)
