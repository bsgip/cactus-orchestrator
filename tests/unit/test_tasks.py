import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from assertical.fixtures.postgres import generate_async_session

from cactus_orchestrator.model import FinalisationStatus, Run
from cactus_orchestrator.tasks import generate_idleteardowntask, teardown_idle_teststack


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
    await generate_idleteardowntask(1, 1, 1)()

    # Assert
    if expect_teardown:
        mock_teardown_teststack.assert_awaited_once()
        mock_finalise_run.assert_awaited_once()
    else:
        mock_teardown_teststack.assert_not_awaited()
        mock_finalise_run.assert_not_awaited()


@pytest.mark.idleteardowntask_enable(10)
@pytest.mark.with_test_db
@pytest.mark.asyncio
@patch("cactus_orchestrator.tasks.teardown_idle_teststack")
async def test_idleteardowntask_valid_session(mock_teardown_idle_teststack, new_app):
    """Ensure valid DB session generated in task."""

    # Act
    with TestClient(new_app) as _:

        # Assert
        assert mock_teardown_idle_teststack.call_count >= 1
        args, _ = mock_teardown_idle_teststack.call_args
        assert isinstance(args[0], AsyncSession)
        assert args[0].bind is not None


@pytest.mark.idleteardowntask_enable(1)
@pytest.mark.asyncio
@patch("cactus_orchestrator.tasks.teardown_idle_teststack")
async def test_idleteardowntask_multiple_triggers(mock_teardown_idle_teststack, new_app):
    """Ensure valid DB session generated in task."""

    # Act
    with TestClient(new_app) as _:
        await asyncio.sleep(3)

    # Assert
    assert mock_teardown_idle_teststack.call_count >= 2


@pytest.mark.with_test_db
@pytest.mark.asyncio
@patch.multiple(
    "cactus_orchestrator.tasks",
    get_resource_names=Mock(),
    is_idle=AsyncMock(),
    is_maxlive_overtime=Mock(),
    finalise_run=AsyncMock(),
    teardown_teststack=AsyncMock(),
)
async def test_teardown_idle_teststack(pg_empty_conn, new_app):
    """Ensure background task triggers actions, with DB unmocked."""
    # Arrange
    from cactus_orchestrator.tasks import is_idle, teardown_teststack, get_resource_names, finalise_run

    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
            """
        )
    )
    # expecting maxlive_overtime=True
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO run (user_id, teststack_id, testprocedure_id, finalisation_status, created_at)
            VALUES (1, 'teststack1', 'testproc1', 0, '2000-01-01T00:00:00Z')
            """
        )
    )
    pg_empty_conn.commit()

    is_idle.return_value = False
    get_resource_names.return_value = ["a"] * 5

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        await teardown_idle_teststack(session, 1, 1)

    # Assert
    teardown_teststack.assert_called_once()
    finalise_run.assert_called_once()
