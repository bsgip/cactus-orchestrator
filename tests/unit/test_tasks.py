import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone

from cactus_orchestrator.tasks import teardown_teststack_task
from cactus_orchestrator.model import FinalisationStatus
from cactus_orchestrator.main import app  # Import FastAPI app


@pytest.mark.asyncio
async def test_teardown_teststack_task():
    """Test that teardown_teststack_task properly handles non-finalized runs."""

    # Mock dependencies
    mock_run = AsyncMock()
    mock_run.teststack_id = "teststack1"
    mock_run.run_id = 1
    mock_run.created_at = datetime.now(timezone.utc)

    with (
        patch("cactus_orchestrator.crud.select_nonfinalised_runs", AsyncMock(return_value=[mock_run])),
        patch("cactus_orchestrator.tasks.is_idle", AsyncMock(return_value=True)),
        patch("cactus_orchestrator.api.run.teardown_teststack", AsyncMock()) as mock_teardown,
        patch("cactus_orchestrator.crud.update_run_finalisation_status", AsyncMock()) as mock_update,
    ):

        await teardown_teststack_task()  # Run the task

        # Assertions
        mock_teardown.assert_called_once()  # Ensure teardown is called
        mock_update.assert_called_once_with(
            ANY, mock_run.run_id, FinalisationStatus.by_timeout, ANY
        )  # Ensure finalization is updated


@pytest.mark.asyncio
async def test_lifespan():
    """Ensure background task runs on app startup & is cancelled on shutdown."""

    with patch("cactus_orchestrator.tasks.teardown_teststack_task", return_value=None) as mock_task:
        with TestClient(app) as client:
            pass  # Simulate app running

        # Ensure background task started
        mock_task.assert_called_once()
