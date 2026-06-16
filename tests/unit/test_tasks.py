import asyncio
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from uuid import uuid4

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fake.generator import generate_class_instance
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.runner import ClientInteraction, ClientInteractionType
from freezegun import freeze_time
from sqlalchemy import select

from cactus_orchestrator.crud import insert_run_for_run_group, select_active_runs_for_user
from cactus_orchestrator.model import Run, RunGroup, RunStatus
from cactus_orchestrator.pod.models import PodResources, RunningPod
from cactus_orchestrator.tasks import destroy_idle_pods, generate_idleteardowntask


@dataclass
class MockedPodman:
    ensure_images: AsyncMock
    fetch_running_pods: AsyncMock
    destroy_pod_resources: AsyncMock

    last_interaction: Mock


@pytest.fixture
def podman_mock() -> Generator[MockedPodman, None, None]:
    with (
        patch("cactus_orchestrator.tasks.ensure_images", new_callable=AsyncMock) as ensure_images,
        patch("cactus_orchestrator.tasks.fetch_running_pods", new_callable=AsyncMock) as fetch_running_pods,
        patch("cactus_orchestrator.tasks.destroy_pod_resources", new_callable=AsyncMock) as destroy_pod_resources,
        patch("cactus_orchestrator.api.run.RunnerClient.last_interaction") as last_interaction,
    ):
        yield MockedPodman(
            ensure_images=ensure_images,
            fetch_running_pods=fetch_running_pods,
            destroy_pod_resources=destroy_pod_resources,
            last_interaction=last_interaction,
        )


@freeze_time("2025-02-03T00:00:00Z")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("idle", "created_at", "expect_teardown"),
    [
        (True, datetime(2025, 2, 3, tzinfo=UTC), True),  # idle timeout,
        (False, datetime(2025, 1, 1, tzinfo=UTC), True),  # max lifetime
        (False, datetime(2025, 2, 3, tzinfo=UTC), False),
    ],
)
@patch("cactus_orchestrator.tasks.select_nonfinalised_runs", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.is_idle", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.destroy_pod_resources", spec=AsyncMock)
@patch("cactus_orchestrator.api.run.finalise_run", spec=AsyncMock)
async def test_generate_idleteardowntask(
    mock_finalise_run,
    mock_destroy_pod_resources,
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
            pod_name="my-pod",
            testprocedure_id="ALL_01",
            created_at=created_at,
            finalised_at=None,
            run_status=RunStatus.initialised,
        )
    ]
    mock_is_idle.return_value = idle
    mock_select_nonfinalised_runs.return_value = mock_runs

    # Act
    await generate_idleteardowntask(1, 1, 1, 100)()

    # Assert
    if expect_teardown:
        mock_destroy_pod_resources.assert_awaited_once()
        mock_finalise_run.assert_awaited_once()
    else:
        mock_destroy_pod_resources.assert_not_awaited()
        mock_finalise_run.assert_not_awaited()


@pytest.mark.idleteardowntask_enable(1)
@pytest.mark.asyncio
async def test_destroy_idle_pods_and_orphans(podman_mock: MockedPodman, pg_base_config, client):
    """Ensure background task triggers actions, with DB unmocked."""

    # Insert some active runs
    async with generate_async_session(pg_base_config) as session:
        # Create some single runs
        provisioning_run_id = (
            await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.provisioning, False)
        ).run_id
        started_run_id = (await insert_run_for_run_group(session, 1, "ALL-02", RunStatus.started, False)).run_id
        terminated_run_id = (await insert_run_for_run_group(session, 1, "ALL-02", RunStatus.terminated, False)).run_id
        finalised_run_id = (
            await insert_run_for_run_group(session, 1, "ALL-02", RunStatus.finalised_by_timeout, False)
        ).run_id

        # Create an active playlist
        p1_r1 = await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.skipped, False)
        p1_r2 = await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.finalised_by_client, False)
        p1_r3 = await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.started, False)
        p1_r4 = await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.initialised, False)
        p1_r1.playlist_execution_id = "abc123"
        p1_r2.playlist_execution_id = "abc123"
        p1_r3.playlist_execution_id = "abc123"
        p1_r4.playlist_execution_id = "abc123"
        p1_run_id = p1_r1.run_id

        # Create an inactive playlist
        p2_r1 = await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.skipped, False)
        p2_r2 = await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.finalised_by_client, False)
        p2_r3 = await insert_run_for_run_group(session, 1, "ALL-01", RunStatus.finalised_by_timeout, False)
        p2_r1.playlist_execution_id = "def456"
        p2_r2.playlist_execution_id = "def456"
        p2_r3.playlist_execution_id = "def456"
        p2_run_id = p2_r1.run_id

        await session.commit()

    # If the task checks for pod liveness - say they are still active
    podman_mock.last_interaction.return_value = ClientInteraction(ClientInteractionType.PROXIED_REQUEST, datetime.now())

    # Create some pods - some will act as orphans and some will not
    podman_mock.fetch_running_pods.side_effect = [
        generate_class_instance(
            RunningPod, run_id=99, resources=generate_class_instance(PodResources, pod_name="run-99")
        ),  # ORPHAN - There is no run-99
        generate_class_instance(
            RunningPod,
            run_id=provisioning_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{provisioning_run_id}"),
        ),  # This is active
        generate_class_instance(
            RunningPod,
            run_id=started_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{started_run_id}"),
        ),  # This is active
        generate_class_instance(
            RunningPod,
            run_id=terminated_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{terminated_run_id}"),
        ),  # ORPHAN - This is terminated
        generate_class_instance(
            RunningPod,
            run_id=finalised_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{finalised_run_id}"),
        ),  # ORPHAN - This is finalised
        generate_class_instance(
            RunningPod,
            run_id=p1_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{p1_run_id}"),
        ),  # This playlist is still active
        generate_class_instance(
            RunningPod,
            run_id=p2_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{p2_run_id}"),
        ),  # ORPHAN - This playlist is finalised
    ]

    # In the test DB runs 1,5,6 and 8 are all from "2024" and due for max life teardown
    expected_finalised_run_ids = [1, 5, 6, 8]
    expected_pod_name_destroys = [
        "run-1",  # Removed as part of run being closed for idle
        "run-5",  # Removed as part of run being closed for idle
        "run-6",  # Removed as part of run being closed for idle
        "run-8",  # Removed as part of run being closed for idle
        "run-99",  # Orphan
        f"run-{terminated_run_id}",  # Orphan
        f"run-{finalised_run_id}",  # Orphan
        f"run-{p2_run_id}",  # Orphan
    ]

    # Let the background task run
    await asyncio.sleep(3)

    # check the DB
    async with generate_async_session(pg_base_config) as session:
        finalised_runs = (
            (await session.execute(select(Run).where(Run.run_id.in_(expected_finalised_run_ids)))).scalars().all()
        )
        for r in finalised_runs:
            assert r.run_status == RunStatus.finalised_by_timeout
            assert r.finalised_at is not None
            assert_nowish(r.finalised_at)

        assert len(await select_active_runs_for_user(session, 1)) == 3, (
            "Playlist 1/2 run entries shouldnt have been touched by idle checks"
        )

    # Check we tore down each teststack
    assert podman_mock.last_interaction.call_count > 0, "We should be checking IDLE status on runs"
    assert set(expected_pod_name_destroys) == set(
        [c.args[1].pod_name for c in podman_mock.destroy_pod_resources.call_args_list]
    ), "We should only be destroying certain pods"


@pytest.mark.asyncio
@patch("cactus_orchestrator.tasks.select_nonfinalised_runs", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.is_idle", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.destroy_pod_resources", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.finalize_teststack_runs", spec=AsyncMock)
async def test_destroy_idle_pods_with_playlist(
    mock_finalize_runs, mock_destroy_pod_resources, mock_is_idle, mock_select_runs
):
    """Test that when a playlist teststack goes idle, all sibling runs in a playlist are finalized together."""

    playlist_execution_id = str(uuid4())

    # Create mock runs with playlist info
    mock_runs = [
        Run(
            run_id=101,
            run_group_id=1,
            pod_name="playlist-teststack",
            testprocedure_id="ALL-01",
            created_at=datetime(2024, 1, 1, tzinfo=UTC),
            finalised_at=None,
            run_status=RunStatus.started,
            playlist_execution_id=playlist_execution_id,
            playlist_order=0,
            run_group=generate_class_instance(RunGroup, certificate_pem=bytes([1])),
        ),
    ]

    # Configure async mocks
    async def async_return(value):
        return value

    mock_select_runs.side_effect = lambda *args, **kwargs: async_return(mock_runs)
    mock_is_idle.side_effect = lambda *args, **kwargs: async_return(True)
    mock_finalize_runs.side_effect = lambda *args, **kwargs: async_return(None)
    mock_destroy_pod_resources.side_effect = lambda *args, **kwargs: async_return(True)

    # Run the teardown task with a mock session
    mock_session = MagicMock()
    mock_session.commit.side_effect = lambda: async_return(None)

    await destroy_idle_pods(mock_session, 3600, 1800, 120)
    mock_finalize_runs.assert_called_once()
    mock_destroy_pod_resources.assert_called_once()
