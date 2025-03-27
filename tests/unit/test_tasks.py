from datetime import datetime, timezone
from unittest.mock import ANY, AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from cactus_orchestrator.main import app
from cactus_orchestrator.model import FinalisationStatus, Run
from cactus_orchestrator.tasks import teardown_teststack_task


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("idle", "created_at", "expect_teardown"),
    [
        (True, datetime.now(tz=timezone.utc), True),  #  idle timeout,
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
            user_id=1,
            teststack_id="abc",
            testprocedure_id="ALL_01",
            created_at=created_at,
            finalised_at=None,
            finalisation_status=FinalisationStatus.not_finalised,
        )
    ]
    mock_is_idle.return_value = idle
    mock_select_nonfinalised_runs.return_value = mock_runs

    # Act
    await teardown_teststack_task()

    # Assert
    if expect_teardown:
        mock_teardown_teststack.assert_awaited_once()
        mock_finalise_run.assert_awaited_once()
    else:
        mock_teardown_teststack.assert_not_awaited()
        mock_finalise_run.assert_not_awaited()


@pytest.mark.asyncio
@patch("cactus_orchestrator.tasks.teardown_teststack_task", return_value=None)
async def test_lifespan(mock_teardown_teststack_task):
    """Ensure background task runs on app startup and is cancelled on shutdown."""
    # Act
    with TestClient(app) as _:
        pass

    # Assert
    mock_teardown_teststack_task.assert_awaited_once()
