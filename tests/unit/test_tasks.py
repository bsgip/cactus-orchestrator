import asyncio
import io
import zipfile
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
from fastapi_async_sqlalchemy import SQLAlchemyMiddleware
from freezegun import freeze_time
from sqlalchemy import select

from cactus_orchestrator.crud import insert_run_for_run_group, select_active_runs_for_user
from cactus_orchestrator.filestore import (
    REPORT_FILE_NAME,
    compliance_finalisation_report_exists,
    fetch_compliance_finalisation_report,
    fetch_run_zip,
    run_report_exists,
    run_zip_exists,
)
from cactus_orchestrator.model import (
    ComplianceRecord,
    ComplianceRequest,
    ComplianceRequestFinalisation,
    Run,
    RunArtifact,
    RunGroup,
    RunStatus,
    User,
)
from cactus_orchestrator.pod.models import PodResources, RunningPod
from cactus_orchestrator.settings import get_current_settings
from cactus_orchestrator.tasks import (
    destroy_idle_pods,
    generate_idleteardowntask,
    migrate_compliance_finalisation,
    migrate_old_compliance_record,
    migrate_run_artifact,
    terminate_dead_pod_runs,
)
from tests.utils.zip import assert_zips_equal, get_zip_arcfile_contents


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

    RUN_GROUP_ID = 1

    # Insert some active runs
    async with generate_async_session(pg_base_config) as session:
        # Create some single runs
        provisioning_run_id = (
            await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.provisioning, False)
        ).run_id
        started_run_id = (await insert_run_for_run_group(session, 1, "ALL-02", RunStatus.started, False)).run_id
        terminated_run_id = (await insert_run_for_run_group(session, 1, "ALL-02", RunStatus.terminated, False)).run_id
        finalised_run_id = (
            await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-02", RunStatus.finalised_by_timeout, False)
        ).run_id
        grace_period_run_id = 98

        # Create an active playlist
        p1_r1 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.skipped, False)
        p1_r2 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.finalised_by_client, False)
        p1_r3 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.started, False)
        p1_r4 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.initialised, False)
        p1_r1.playlist_execution_id = "abc123"
        p1_r2.playlist_execution_id = "abc123"
        p1_r3.playlist_execution_id = "abc123"
        p1_r4.playlist_execution_id = "abc123"
        p1_run_id = p1_r1.run_id

        # Create an inactive playlist
        p2_r1 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.skipped, False)
        p2_r2 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.finalised_by_client, False)
        p2_r3 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.finalised_by_timeout, False)
        p2_r1.playlist_execution_id = "def456"
        p2_r2.playlist_execution_id = "def456"
        p2_r3.playlist_execution_id = "def456"
        p2_run_id = p2_r1.run_id

        # Active single run whose pod was deleted out-of-band (entirely missing from podman)
        dead_pod_run = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.started, False)
        dead_pod_run.pod_name = f"run-{dead_pod_run.run_id}"
        dead_pod_run_id = dead_pod_run.run_id

        # Active single run whose pod is still present in podman but has crashed/exited (is_running=False)
        crashed_pod_run = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.started, False)
        crashed_pod_run.pod_name = f"run-{crashed_pod_run.run_id}"
        crashed_pod_run_id = crashed_pod_run.run_id

        # Active playlist whose active run's pod was deleted out-of-band - all active siblings should terminate too
        p3_r1 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.finalised_by_client, False)
        p3_r2 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.started, False)
        p3_r3 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.initialised, False)
        p3_r1.playlist_execution_id = "ghi789"
        p3_r2.playlist_execution_id = "ghi789"
        p3_r3.playlist_execution_id = "ghi789"
        p3_r2.pod_name = f"run-{p3_r2.run_id}"
        p3_r3.pod_name = p3_r2.pod_name  # playlist siblings share the same pod
        p3_run_id = p3_r2.run_id
        p3_r3_run_id = p3_r3.run_id

        # Create an active playlist mid-session where the active test has just been advanced to via /next-test
        # but not yet started - only 'initialised' (active, not-yet-started) + 'finalised' rows, no
        # 'provisioning'/'started' row present. This should NOT be treated as orphaned (regression coverage for
        # the playlist migration's orphan-pod rule).
        p4_r1 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.finalised_by_client, False)
        p4_r2 = await insert_run_for_run_group(session, RUN_GROUP_ID, "ALL-01", RunStatus.initialised, False)
        p4_r1.playlist_execution_id = "jkl012"
        p4_r2.playlist_execution_id = "jkl012"
        p4_run_id = p4_r1.run_id

        await session.commit()

    # If the task checks for pod liveness - say they are still active
    podman_mock.last_interaction.return_value = ClientInteraction(ClientInteractionType.PROXIED_REQUEST, datetime.now())

    # Create some pods - some will act as orphans and some will not
    podman_mock.fetch_running_pods.return_value = [
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=99,
            resources=generate_class_instance(PodResources, pod_name="run-99"),
        ),  # ORPHAN - There is no run-99
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=grace_period_run_id,
            created_time=datetime.now(UTC),
            resources=generate_class_instance(PodResources, pod_name=f"run-{grace_period_run_id}"),
        ),  # ORPHAN - but within the grace period so it WON'T be touched - There is no run-98
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=provisioning_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{provisioning_run_id}"),
        ),  # This is active
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=started_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{started_run_id}"),
        ),  # This is active
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=terminated_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{terminated_run_id}"),
        ),  # ORPHAN - This is terminated
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=finalised_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{finalised_run_id}"),
        ),  # ORPHAN - This is finalised
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=p1_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{p1_run_id}"),
        ),  # This playlist is still active
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=p2_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{p2_run_id}"),
        ),  # ORPHAN - This playlist is finalised
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=crashed_pod_run_id,
            is_running=False,
            resources=generate_class_instance(PodResources, pod_name=f"run-{crashed_pod_run_id}"),
        ),  # DEAD - pod is present but has crashed/exited (is_running=False)
        # NOTE: dead_pod_run_id and p3_run_id are deliberately absent - simulating a pod deleted out-of-band
        generate_class_instance(
            RunningPod,
            run_group_id=RUN_GROUP_ID,
            run_id=p4_run_id,
            resources=generate_class_instance(PodResources, pod_name=f"run-{p4_run_id}"),
        ),  # This playlist's active test is only 'initialised' (advanced, not yet started) - still active
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
        f"run-{dead_pod_run_id}",  # Dead pod - deleted out-of-band
        f"run-{crashed_pod_run_id}",  # Dead pod - crashed/exited
        f"run-{p3_run_id}",  # Dead pod - playlist active run's pod deleted out-of-band
    ]
    expected_terminated_run_ids = [dead_pod_run_id, crashed_pod_run_id, p3_run_id, p3_r3_run_id]

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

        terminated_runs = (
            (await session.execute(select(Run).where(Run.run_id.in_(expected_terminated_run_ids)))).scalars().all()
        )
        assert len(terminated_runs) == len(expected_terminated_run_ids)
        for r in terminated_runs:
            assert r.run_status == RunStatus.terminated
            assert r.finalised_at is not None
            assert_nowish(r.finalised_at)

        assert len(await select_active_runs_for_user(session, 1)) == 3, (
            "Playlist 1/2 run entries shouldnt have been touched by idle checks"
        )

    # Check we tore down each teststack
    assert podman_mock.last_interaction.call_count > 0, "We should be checking IDLE status on runs"

    all_destroyed_resource_names = [c.args[1].pod_name for c in podman_mock.destroy_pod_resources.call_args_list]
    assert set(expected_pod_name_destroys) == set(all_destroyed_resource_names), (
        "We should only be destroying certain pods"
    )


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("pod_name_in_run", "running_pods", "expect_terminate"),
    [
        ("run-101", [], True),  # pod missing entirely - deleted out-of-band
        ("run-101", [generate_class_instance(RunningPod, name="run-101", is_running=False)], True),  # crashed/exited
        ("run-101", [generate_class_instance(RunningPod, name="run-101", is_running=True)], False),  # still alive
        (None, [], False),  # pod never created yet (still provisioning) - nothing to reconcile
    ],
)
@patch("cactus_orchestrator.tasks.select_nonfinalised_runs", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.destroy_pod_resources", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.finalize_teststack_runs", spec=AsyncMock)
async def test_terminate_dead_pod_runs(
    mock_finalize_runs, mock_destroy_pod_resources, mock_select_runs, pod_name_in_run, running_pods, expect_terminate
):
    """Verify a run is only terminated when its pod is missing or present-but-not-running."""

    mock_run = Run(
        run_id=101,
        run_group_id=1,
        pod_name=pod_name_in_run,
        testprocedure_id="ALL-01",
        created_at=datetime(2024, 1, 1, tzinfo=UTC),
        finalised_at=None,
        run_status=RunStatus.started,
    )

    async def async_return(value):
        return value

    mock_select_runs.side_effect = lambda *args, **kwargs: async_return([mock_run])
    mock_finalize_runs.side_effect = lambda *args, **kwargs: async_return(None)
    mock_destroy_pod_resources.side_effect = lambda *args, **kwargs: async_return(True)

    mock_session = MagicMock()
    mock_session.commit.side_effect = lambda: async_return(None)

    await terminate_dead_pod_runs(mock_session, running_pods, 120)

    if expect_terminate:
        mock_finalize_runs.assert_called_once()
        assert mock_finalize_runs.call_args.args[4] == RunStatus.terminated
        mock_destroy_pod_resources.assert_called_once()
    else:
        mock_finalize_runs.assert_not_called()
        mock_destroy_pod_resources.assert_not_called()


@pytest.mark.asyncio
@patch("cactus_orchestrator.tasks.select_nonfinalised_runs", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.destroy_pod_resources", spec=AsyncMock)
@patch("cactus_orchestrator.tasks.finalize_teststack_runs", spec=AsyncMock)
async def test_terminate_dead_pod_runs_with_playlist(mock_finalize_runs, mock_destroy_pod_resources, mock_select_runs):
    """When a playlist's active run's pod has died, only one terminate/destroy call is made for that teststack."""

    playlist_execution_id = str(uuid4())
    mock_runs = [
        Run(
            run_id=201,
            run_group_id=1,
            pod_name="playlist-teststack",
            testprocedure_id="ALL-01",
            created_at=datetime(2024, 1, 1, tzinfo=UTC),
            finalised_at=None,
            run_status=RunStatus.started,
            playlist_execution_id=playlist_execution_id,
            playlist_order=0,
        ),
        Run(
            run_id=202,
            run_group_id=1,
            pod_name="playlist-teststack",
            testprocedure_id="ALL-01",
            created_at=datetime(2024, 1, 1, tzinfo=UTC),
            finalised_at=None,
            run_status=RunStatus.initialised,
            playlist_execution_id=playlist_execution_id,
            playlist_order=1,
        ),
    ]

    async def async_return(value):
        return value

    mock_select_runs.side_effect = lambda *args, **kwargs: async_return(mock_runs)
    mock_finalize_runs.side_effect = lambda *args, **kwargs: async_return(None)
    mock_destroy_pod_resources.side_effect = lambda *args, **kwargs: async_return(True)

    mock_session = MagicMock()
    mock_session.commit.side_effect = lambda: async_return(None)

    await terminate_dead_pod_runs(mock_session, [], 120)

    # Both runs share one pod/teststack - only the first (playlist-order 0) run should trigger the calls,
    # the second is skipped as its playlist has already been processed
    mock_finalize_runs.assert_called_once()
    mock_destroy_pod_resources.assert_called_once()


def gen_zip(seed: int, extra_files: list[tuple[str, bytes]]) -> bytes:
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("foo/bar", f"data{seed * 2}")
        archive.writestr("baz", f"data{seed * 3}")

        for name, data in extra_files:
            archive.writestr(name, data)
    return zip_buffer.getvalue()


async def test_migrate_run_artifact(pg_empty_config):
    """Test that migrate_run_artifact handles a few seperate situations"""

    # Arrange
    from cactus_orchestrator.main import generate_app

    settings = get_current_settings()
    SQLAlchemyMiddleware(generate_app(settings), db_url=str(settings.orchestrator_database_url), commit_on_exit=False)

    run_5_zip = gen_zip(555, [])
    run_6_zip = gen_zip(666, [])
    run_7_report = bytes([7, 64, 1, 4, 77, 0, 1, 5])
    run_7_zip = gen_zip(777, [("foo.pdf", run_7_report)])
    run_8_report = bytes([8, 69, 67])
    run_8_zip = gen_zip(888, [("foo.pdf", run_8_report)])
    async with generate_async_session(pg_empty_config) as session:
        user = generate_class_instance(User, optional_is_none=True)
        run_group = generate_class_instance(RunGroup, optional_is_none=True, user=user)
        session.add(user)
        session.add(run_group)

        # Run 1,2 - no artifact
        session.add(
            generate_class_instance(
                Run,
                seed=101,
                run_id=1,
                run_artifact_migrated=False,
                run_artifact_id=None,
                run_artifact_migrated_error=None,
                warnings=None,
                run_group=run_group,
            )
        )
        session.add(
            generate_class_instance(
                Run,
                seed=202,
                run_id=2,
                run_artifact_migrated=True,
                run_artifact_id=None,
                run_artifact_migrated_error=None,
                warnings=None,
                run_group=run_group,
            )
        )

        # Run 3,4 - Junk ZIP file that will fail to load
        session.add(
            generate_class_instance(
                Run,
                seed=303,
                run_id=3,
                run_artifact_migrated=False,
                run_artifact_migrated_error=None,
                run_artifact=generate_class_instance(RunArtifact, seed=33, file_data=bytes([0, 2, 3])),
                warnings=None,
                run_group=run_group,
            )
        )
        session.add(
            generate_class_instance(
                Run,
                seed=404,
                run_id=4,
                run_artifact_migrated=True,
                run_artifact_migrated_error=None,
                run_artifact=generate_class_instance(RunArtifact, seed=44, file_data=bytes([0, 4, 5])),
                warnings=None,
                run_group=run_group,
            )
        )

        # Run 5,6 - ZIP file with no PDF
        session.add(
            generate_class_instance(
                Run,
                seed=505,
                run_id=5,
                run_artifact_migrated=False,
                run_artifact_migrated_error=None,
                run_artifact=generate_class_instance(RunArtifact, seed=55, file_data=run_5_zip),
                warnings=None,
                run_group=run_group,
            )
        )
        session.add(
            generate_class_instance(
                Run,
                seed=606,
                run_id=6,
                run_artifact_migrated=True,
                run_artifact_migrated_error=None,
                run_artifact=generate_class_instance(RunArtifact, seed=66, file_data=run_6_zip),
                warnings=None,
                run_group=run_group,
            )
        )

        # Run 7,8 - ZIP file with PDFs
        session.add(
            generate_class_instance(
                Run,
                seed=707,
                run_id=7,
                run_artifact_migrated=False,
                run_artifact_migrated_error=None,
                run_artifact=generate_class_instance(RunArtifact, seed=77, file_data=run_7_zip),
                warnings=None,
                run_group=run_group,
            )
        )
        session.add(
            generate_class_instance(
                Run,
                seed=808,
                run_id=8,
                run_artifact_migrated=True,
                run_artifact_migrated_error=None,
                run_artifact=generate_class_instance(RunArtifact, seed=88, file_data=run_8_zip),
                warnings=None,
                run_group=run_group,
            )
        )
        await session.commit()

    # Act
    await migrate_run_artifact()

    # Assert
    async with generate_async_session(pg_empty_config) as session:
        runs = (await session.execute(select(Run).order_by(Run.run_id))).scalars().all()
        assert len(runs) == 8
        assert all(r.run_artifact_migrated for r in runs)
        assert [bool(r.run_artifact_migrated_error) for r in runs] == [
            False,
            False,
            True,
            False,
            False,
            False,
            False,
            False,
        ], "Matching whether there was a migration error"
        assert [run_zip_exists(settings.file_store_path, r.run_id) for r in runs] == [
            False,
            False,
            False,
            False,
            True,
            False,  # was marked as migrated
            True,
            False,  # was marked as migrated
        ], "Matching whether ANY data was put in the file store"
        assert [run_report_exists(settings.file_store_path, r.run_id) for r in runs] == [
            False,
            False,
            False,
            False,
            False,
            False,
            True,
            False,  # was marked as migrated
        ], "Matching whether ANY report data was put in the file store"

        actual_run_7_zip = fetch_run_zip(settings.file_store_path, 7)
        assert_zips_equal(run_7_zip, actual_run_7_zip, {"foo.pdf", REPORT_FILE_NAME})
        assert get_zip_arcfile_contents(actual_run_7_zip, REPORT_FILE_NAME) == run_7_report


async def test_migrate_compliance_finalisation(pg_empty_config):
    """Test that migrate_compliance_finalisation handles a few seperate situations"""

    # Arrange
    from cactus_orchestrator.main import generate_app

    settings = get_current_settings()
    SQLAlchemyMiddleware(generate_app(settings), db_url=str(settings.orchestrator_database_url), commit_on_exit=False)

    req_3_data = bytes([3, 3, 3])
    req_4_data = bytes([4, 4, 4])
    async with generate_async_session(pg_empty_config) as session:
        user = generate_class_instance(User, optional_is_none=True)
        cr = generate_class_instance(
            ComplianceRequest, optional_is_none=True, created_by_user=user, updated_by_user=user
        )
        session.add(user)
        session.add(cr)
        await session.flush()

        # finalisation 1,2 - no artifact
        session.add(
            generate_class_instance(
                ComplianceRequestFinalisation,
                seed=101,
                compliance_request_finalisation_id=1,
                compliance_request_id=cr.compliance_request_id,
                created_by=user.user_id,
                file_data=bytes([]),
                file_data_migrated=False,
                file_data_migrated_error=None,
            )
        )
        session.add(
            generate_class_instance(
                ComplianceRequestFinalisation,
                seed=202,
                compliance_request_finalisation_id=2,
                compliance_request_id=cr.compliance_request_id,
                created_by=user.user_id,
                file_data=bytes([]),
                file_data_migrated=True,
                file_data_migrated_error=None,
            )
        )

        # finalisation 3,4 - has artifact
        session.add(
            generate_class_instance(
                ComplianceRequestFinalisation,
                seed=303,
                compliance_request_finalisation_id=3,
                compliance_request_id=cr.compliance_request_id,
                created_by=user.user_id,
                file_data=req_3_data,
                file_data_migrated=False,
                file_data_migrated_error=None,
            )
        )
        session.add(
            generate_class_instance(
                ComplianceRequestFinalisation,
                seed=404,
                compliance_request_finalisation_id=4,
                compliance_request_id=cr.compliance_request_id,
                created_by=user.user_id,
                file_data=req_4_data,
                file_data_migrated=True,
                file_data_migrated_error=None,
            )
        )
        await session.commit()

    # Act
    await migrate_compliance_finalisation()

    # Assert
    async with generate_async_session(pg_empty_config) as session:
        crs = (
            (
                await session.execute(
                    select(ComplianceRequestFinalisation).order_by(
                        ComplianceRequestFinalisation.compliance_request_finalisation_id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(crs) == 4
        assert all(cr.file_data_migrated for cr in crs)
        assert [bool(r.file_data_migrated_error) for r in crs] == [
            False,
            False,
            False,
            False,
        ], "Matching whether there was a migration error"
        assert [
            compliance_finalisation_report_exists(settings.file_store_path, cr.compliance_request_finalisation_id)
            for cr in crs
        ] == [
            False,
            False,
            True,
            False,  # Marked as migrated
        ], "Matching whether ANY data was put in the file store"

        assert fetch_compliance_finalisation_report(settings.file_store_path, 3) == req_3_data


async def test_migrate_old_compliance_record(pg_empty_config):
    """Test that migrate_old_compliance_record handles a few seperate situations"""

    # Arrange
    from cactus_orchestrator.main import generate_app

    settings = get_current_settings()
    SQLAlchemyMiddleware(generate_app(settings), db_url=str(settings.orchestrator_database_url), commit_on_exit=False)

    req_3_data = bytes([3, 3, 3])
    req_4_data = bytes([4, 4, 4])
    async with generate_async_session(pg_empty_config) as session:
        user = generate_class_instance(User, optional_is_none=True)
        run_group = generate_class_instance(RunGroup, optional_is_none=True, user=user)
        session.add(user)
        session.add(run_group)

        await session.flush()

        # record 1,2 - no artifact
        session.add(
            generate_class_instance(
                ComplianceRecord,
                seed=101,
                compliance_record_id=1,
                requester_id=user.user_id,
                run_group_id=run_group.run_group_id,
                file_data=bytes([]),
                file_data_migrated=False,
                file_data_migrated_error=None,
            )
        )
        session.add(
            generate_class_instance(
                ComplianceRecord,
                seed=202,
                compliance_record_id=2,
                requester_id=user.user_id,
                run_group_id=run_group.run_group_id,
                file_data=bytes([]),
                file_data_migrated=True,
                file_data_migrated_error=None,
            )
        )

        # record 3,4 - has artifact
        session.add(
            generate_class_instance(
                ComplianceRecord,
                seed=303,
                compliance_record_id=3,
                requester_id=user.user_id,
                run_group_id=run_group.run_group_id,
                file_data=req_3_data,
                file_data_migrated=False,
                file_data_migrated_error=None,
            )
        )
        session.add(
            generate_class_instance(
                ComplianceRecord,
                seed=404,
                compliance_record_id=4,
                requester_id=user.user_id,
                run_group_id=run_group.run_group_id,
                file_data=req_4_data,
                file_data_migrated=True,
                file_data_migrated_error=None,
            )
        )
        await session.commit()

    # Act
    await migrate_old_compliance_record()

    # Assert
    async with generate_async_session(pg_empty_config) as session:
        crs = (
            (await session.execute(select(ComplianceRecord).order_by(ComplianceRecord.compliance_record_id)))
            .scalars()
            .all()
        )
        assert len(crs) == 4
        assert all(cr.file_data_migrated for cr in crs)
        assert [bool(r.file_data_migrated_error) for r in crs] == [
            False,
            False,
            False,
            False,
        ], "Matching whether there was a migration error"
