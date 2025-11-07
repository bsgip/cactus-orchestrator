from datetime import datetime, timezone

import pytest
from assertical.asserts.time import assert_nowish
from assertical.asserts.type import assert_dict_type, assert_list_type
from assertical.fixtures.postgres import generate_async_session
from cactus_test_definitions import CSIPAusVersion
from cactus_test_definitions.client import TestProcedureId
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError, NoResultFound

from cactus_orchestrator.auth import UserContext
from cactus_orchestrator.crud import (
    ProcedureRunAggregated,
    insert_run_for_run_group,
    insert_run_group,
    insert_user,
    select_active_runs_for_user,
    select_group_runs_aggregated_by_procedure,
    select_group_runs_for_procedure,
    select_nonfinalised_runs,
    select_run_group_counts_for_user,
    select_run_group_for_user,
    select_run_groups_by_user,
    select_run_groups_for_user,
    select_runs_for_group,
    select_user,
    select_user_from_run_group,
    select_user_run,
    select_user_run_with_artifact,
    select_users,
    update_run_run_status,
    update_run_with_runartifact_and_finalise,
    update_user_name,
)
from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User


@pytest.mark.asyncio
async def test_insert_user(pg_empty_config):
    """Tests that a new user can be inserted and that rollback/commit interact with it as expected"""
    # Arrange
    uc1 = UserContext(subject_id="sub1", issuer_id="issuer1")
    uc2 = UserContext(subject_id="sub2", issuer_id="issuer2")

    # Act
    async with generate_async_session(pg_empty_config) as s:
        user1 = await insert_user(s, uc1)

        assert user1.user_id == 1
        assert user1.subscription_domain is None
        assert isinstance(user1.is_static_uri, bool)
        assert user1.subject_id == uc1.subject_id
        assert user1.issuer_id == uc1.issuer_id

        await s.commit()

    # Test we can rollback
    async with generate_async_session(pg_empty_config) as s:
        user2 = await insert_user(s, uc2)

        assert user2.user_id == 2
        assert user2.subscription_domain is None
        assert isinstance(user2.is_static_uri, bool)
        assert user2.subject_id == uc2.subject_id
        assert user2.issuer_id == uc2.issuer_id

        await s.rollback()

    async with generate_async_session(pg_empty_config) as s:
        with pytest.raises(IntegrityError):
            await insert_user(s, uc1)

    # Test we can insert as expected
    async with generate_async_session(pg_empty_config) as s:
        user3 = await insert_user(s, uc2)

        assert user3.user_id == 4, "The sequence would have been incremented for the above two insert attempts"
        assert user3.subscription_domain is None
        assert isinstance(user3.is_static_uri, bool)
        assert user3.subject_id == uc2.subject_id
        assert user3.issuer_id == uc2.issuer_id

        await s.commit()

    # Quick check of the database
    async with generate_async_session(pg_empty_config) as s:
        run_group_count = (await s.execute(select(func.count()).select_from(RunGroup))).scalar_one()
        assert run_group_count == 2

        user_count = (await s.execute(select(func.count()).select_from(User))).scalar_one()
        assert user_count == 2


@pytest.mark.asyncio
async def test_insert_run_group(pg_base_config):
    """Tests that new groups can be added and appropriately interact with commit/rollback"""

    # Act
    async with generate_async_session(pg_base_config) as s:
        group1 = await insert_run_group(s, user_id=2, csip_aus_version=CSIPAusVersion.RELEASE_1_2.value)

        assert group1.run_group_id == 4
        assert group1.user_id == 2
        assert group1.name and isinstance(group1.name, str)
        assert group1.csip_aus_version == CSIPAusVersion.RELEASE_1_2.value
        assert_nowish(group1.created_at)
        await s.commit()

    # Test we can rollback
    async with generate_async_session(pg_base_config) as s:
        group2 = await insert_run_group(s, user_id=2, csip_aus_version=CSIPAusVersion.BETA_1_3_STORAGE.value)

        assert group2.run_group_id == 5
        assert group2.user_id == 2
        assert group2.name and isinstance(group2.name, str)
        assert group2.csip_aus_version == CSIPAusVersion.BETA_1_3_STORAGE.value
        assert_nowish(group2.created_at)
        await s.rollback()

    # Test we can insert as expected
    async with generate_async_session(pg_base_config) as s:
        group3 = await insert_run_group(s, user_id=2, csip_aus_version=CSIPAusVersion.RELEASE_1_2.value)

        assert group3.run_group_id == 6
        assert group3.user_id == 2
        assert group3.name and isinstance(group3.name, str)
        assert group3.csip_aus_version == CSIPAusVersion.RELEASE_1_2.value
        assert_nowish(group3.created_at)
        await s.commit()

    # Quick check of the database
    async with generate_async_session(pg_base_config) as s:
        run_group_count = (await s.execute(select(func.count()).select_from(RunGroup))).scalar_one()
        assert run_group_count == 5, "We added two to the existing three run groups"


@pytest.mark.parametrize(
    "run_group_ids, expected", [([1, 2], {1: 6, 2: 1}), ([1, 2, 3], {1: 6, 2: 1, 3: 1}), ([], {}), ([1, 99], {1: 6})]
)
@pytest.mark.asyncio
async def test_select_run_group_counts_for_user(pg_base_config, run_group_ids, expected):
    async with generate_async_session(pg_base_config) as session:
        result = await select_run_group_counts_for_user(session, run_group_ids)
        assert result == expected
        assert_dict_type(int, int, result, len(expected))


@pytest.mark.asyncio
async def test_select_run_groups_by_user(pg_base_config):
    async with generate_async_session(pg_base_config) as session:
        run_groups = await select_run_groups_by_user(session)
        assert run_groups[1] == [1, 2]  # user_id=1
        assert run_groups[2] == [3]  # user_id=2


@pytest.mark.asyncio
async def test_select_users(pg_base_config):
    async with generate_async_session(pg_base_config) as session:
        users = await select_users(session)
        assert_list_type(User, users, 3)


@pytest.mark.parametrize("run_group_id,user_id", [(1, 1), (2, 1), (3, 2), (4, None)])
@pytest.mark.asyncio
async def test_select_user_from_run_group(pg_base_config, run_group_id, user_id):
    async with generate_async_session(pg_base_config) as session:
        user = await select_user_from_run_group(session=session, run_group_id=run_group_id)
        assert user.user_id if user else None == user_id


@pytest.mark.parametrize(
    "user_id, user_name",
    [(1, "Foo Bar"), (2, "example@example.com"), (1, "Mr. Mister")],
)
@pytest.mark.asyncio
async def test_update_user_name(pg_base_config, user_id: int, user_name: str):
    """Test updating user name of user"""

    # Act
    async with generate_async_session(pg_base_config) as session:
        await update_user_name(session, user_id, user_name)
        await session.commit()

    # Assert
    async with generate_async_session(pg_base_config) as session:
        updated_user = (await session.execute(select(User).where(User.user_id == user_id))).scalar_one()
        assert updated_user.user_name == user_name


@pytest.mark.asyncio
async def test_select_run_groups_user(pg_base_config):
    """Test fetching all run groups for a user (no filters)."""

    async with generate_async_session(pg_base_config) as session:
        run_groups = await select_run_groups_for_user(session, 1)
        assert_list_type(RunGroup, run_groups, 2)

        run_groups = await select_run_groups_for_user(session, 2)
        assert_list_type(RunGroup, run_groups, 1)

        run_groups = await select_run_groups_for_user(session, 3)
        assert_list_type(RunGroup, run_groups, 0)


@pytest.mark.asyncio
async def test_select_active_runs_for_user(pg_base_config):
    """Test fetching runs across multiple groups for a user"""

    async with generate_async_session(pg_base_config) as session:
        user_1_runs = await select_active_runs_for_user(session, 1)
        assert_list_type(Run, user_1_runs, 3)
        assert [8, 5, 1] == [r.run_id for r in user_1_runs]
        assert all([isinstance(r.run_group, RunGroup) for r in user_1_runs])

        user_2_runs = await select_active_runs_for_user(session, 2)
        assert_list_type(Run, user_2_runs, 1)
        assert [6] == [r.run_id for r in user_2_runs]
        assert all([isinstance(r.run_group, RunGroup) for r in user_2_runs])

        user_3_runs = await select_active_runs_for_user(session, 3)
        assert_list_type(Run, user_3_runs, 0)

        user_dne_runs = await select_active_runs_for_user(session, 99)
        assert_list_type(Run, user_dne_runs, 0)


@pytest.mark.parametrize("with_cert", [True, False])
@pytest.mark.asyncio
async def test_select_run_group_user(pg_base_config, with_cert: bool):
    """Test fetching a single run group for a user"""

    async with generate_async_session(pg_base_config) as session:
        assert (await select_run_group_for_user(session, 1, 3, with_cert)) is None, "Wrong user"
        assert (await select_run_group_for_user(session, 2, 1, with_cert)) is None, "Wrong user"
        assert (await select_run_group_for_user(session, 1, 99, with_cert)) is None, "Bad ID"

        run_group_1 = await select_run_group_for_user(session, 1, 1, with_cert)
        assert isinstance(run_group_1, RunGroup)
        assert run_group_1.run_group_id == 1
        assert run_group_1.is_device_cert is True
        assert run_group_1.certificate_id == 11
        run_group_2 = await select_run_group_for_user(session, 1, 2, with_cert)
        assert isinstance(run_group_2, RunGroup)
        assert run_group_2.run_group_id == 2
        assert run_group_2.is_device_cert is None
        run_group_3 = await select_run_group_for_user(session, 2, 3, with_cert)
        assert isinstance(run_group_3, RunGroup)
        assert run_group_3.run_group_id == 3
        assert run_group_3.is_device_cert is False
        assert run_group_3.certificate_id == 33

        if with_cert:
            assert run_group_1.certificate_pem == bytes([1])
            assert run_group_2.certificate_pem is None
            assert run_group_3.certificate_pem == bytes([3])
        else:
            with pytest.raises(Exception):
                run_group_1.certificate_pem
            with pytest.raises(Exception):
                run_group_2.certificate_pem
            with pytest.raises(Exception):
                run_group_3.certificate_pem


@pytest.mark.asyncio
async def test_insert_user_unique_constraint(pg_base_config):
    """test exception raised on unique constraint breach"""
    # Arrange
    uc = UserContext(subject_id="a", issuer_id="a")

    async with generate_async_session(pg_base_config) as s:
        _ = await insert_user(s, uc)
        await s.commit()

    with pytest.raises(IntegrityError):
        async with generate_async_session(pg_base_config) as s:
            _ = await insert_user(s, uc)
            await s.commit()


@pytest.mark.parametrize(
    "run_id, finalised, created_at, expected_run_ids",
    [
        (1, None, None, [8, 7, 4, 3, 2, 1]),
        (2, None, None, [5]),
        (3, None, None, [6]),
        (99, None, None, []),
        (1, True, None, [7, 4, 3, 2]),
        (1, False, None, [8, 1]),
        (1, None, datetime(2024, 1, 1, 0, 1, tzinfo=timezone.utc), [8, 7, 4, 3, 2, 1]),
        (1, None, datetime(2024, 1, 1, 0, 5, tzinfo=timezone.utc), [8, 7]),
        (1, True, datetime(2024, 1, 1, 0, 3, 5, tzinfo=timezone.utc), [7, 4]),
    ],
)
@pytest.mark.asyncio
async def test_select_runs_for_group(
    pg_base_config, run_id: int, finalised: bool | None, created_at: datetime | None, expected_run_ids: list[int]
):
    """Test fetching all runs for a user (no filters)."""

    async with generate_async_session(pg_base_config) as session:
        runs = await select_runs_for_group(session, run_id, finalised, created_at)
        assert expected_run_ids == [r.run_id for r in runs]
        assert_list_type(Run, runs, len(expected_run_ids))


@pytest.mark.asyncio
async def test_insert_run_for_run_group(pg_base_config):

    async with generate_async_session(pg_base_config) as session:
        count_before = (await session.execute(select(func.count()).select_from(Run))).scalar_one()

    # Act
    async with generate_async_session(pg_base_config) as session:
        run_id = await insert_run_for_run_group(session, 2, "teststack-new", "ALL_20", RunStatus.initialised, True)
        assert isinstance(run_id, int)
        await session.commit()

    # Assert
    async with generate_async_session(pg_base_config) as session:
        count_after = (await session.execute(select(func.count()).select_from(Run))).scalar_one()
        assert count_after == (count_before + 1)

        new_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one()
        assert new_run.teststack_id == "teststack-new"
        assert new_run.testprocedure_id == "ALL_20"
        assert new_run.run_status == RunStatus.initialised
        assert new_run.is_device_cert is True
        assert_nowish(new_run.created_at)
        assert new_run.finalised_at is None


@pytest.mark.asyncio
async def test_select_nonfinalised_runs(pg_base_config):
    """Test selecting only non-finalised runs."""

    async with generate_async_session(pg_base_config) as session:
        runs = await select_nonfinalised_runs(session)
        assert [1, 5, 6, 8] == [r.run_id for r in runs]
        assert_list_type(Run, runs, 4)


@pytest.mark.parametrize(
    "run_id, run_status",
    [(1, RunStatus.finalised_by_timeout), (1, RunStatus.finalised_by_client), (6, RunStatus.terminated)],
)
@pytest.mark.asyncio
async def test_update_run_run_status(pg_base_config, run_id: int, run_status: RunStatus):
    """Test updating the finalisation status of a run."""
    finalised_at = datetime(2025, 1, 1, tzinfo=timezone.utc)

    # Act
    async with generate_async_session(pg_base_config) as session:
        await update_run_run_status(session, run_id, run_status, finalised_at)
        await session.commit()

    # Assert
    async with generate_async_session(pg_base_config) as session:
        updated_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one()
        assert updated_run.finalised_at == finalised_at
        assert updated_run.run_status == run_status


@pytest.mark.parametrize(
    "user_id, run_id, success",
    [(1, 1, True), (1, 5, True), (2, 1, False), (1, 6, False), (1, 99, False), (99, 1, False)],
)
@pytest.mark.asyncio
async def test_select_user_run(pg_base_config, user_id: int, run_id: int, success: bool):
    """Test selecting a run for a given user."""
    # Act
    async with generate_async_session(pg_base_config) as session:

        if success:
            run = await select_user_run(session, user_id, run_id)
            assert run is not None
            assert isinstance(run, Run)
            assert isinstance(run.run_group, RunGroup), "RunGroup should be populated"
            assert run.run_id == run_id
        else:
            with pytest.raises(NoResultFound):
                await select_user_run(session, user_id, run_id)


@pytest.mark.parametrize(
    "user_id, run_id, run_status, finalised_at, all_criteria_met",
    [
        (1, 1, RunStatus.finalised_by_client, datetime(2025, 1, 1, tzinfo=timezone.utc), True),
        (1, 1, RunStatus.finalised_by_timeout, datetime(2025, 2, 2, tzinfo=timezone.utc), False),
        (1, 1, RunStatus.finalised_by_client, datetime(2025, 3, 3, tzinfo=timezone.utc), None),
        (2, 6, RunStatus.finalised_by_client, datetime(2025, 1, 1, tzinfo=timezone.utc), True),
    ],
)
@pytest.mark.asyncio
async def test_update_run_with_runartifact_and_finalise(
    pg_base_config, user_id, run_id, run_status, finalised_at, all_criteria_met
):
    """Test updating a run with a run artifact and finalisation status."""
    # Arrange
    async with generate_async_session(pg_base_config) as session:
        run_artifact = RunArtifact(compression="gzip", file_data=bytes([1, 5, 6]))
        session.add(run_artifact)
        await session.flush()
        run_artifact_id = run_artifact.run_artifact_id
        await session.commit()

    # Act
    async with generate_async_session(pg_base_config) as session:
        run = await select_user_run(session, user_id, run_id)
        await update_run_with_runartifact_and_finalise(
            session, run, run_artifact_id, run_status, finalised_at, all_criteria_met
        )
        await session.commit()

    # Assert
    async with generate_async_session(pg_base_config) as session:
        updated_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one()
        assert updated_run.run_artifact_id == run_artifact_id
        assert updated_run.run_status == run_status
        assert updated_run.finalised_at == finalised_at
        assert updated_run.all_criteria_met is all_criteria_met


@pytest.mark.asyncio
async def test_select_user_run_with_artifact(pg_base_config):
    """Test selecting run with run artifact joined in load."""

    # Arrange
    run_artifact_bytes = bytes([1, 5, 6, 0, 127])
    run_id = 4
    user_id = 1
    async with generate_async_session(pg_base_config) as session:
        run_artifact = RunArtifact(compression="gzip", file_data=run_artifact_bytes)
        session.add(run_artifact)
        await session.flush()
        run_artifact_id = run_artifact.run_artifact_id

        updated_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one()
        updated_run.run_artifact_id = run_artifact_id

        await session.commit()

    async with generate_async_session(pg_base_config) as session:
        run = await select_user_run_with_artifact(session, user_id, run_id)
        assert run.run_artifact_id == run_artifact_id
        assert run.run_artifact.compression == "gzip"
        assert run.run_artifact.file_data == run_artifact_bytes


@pytest.mark.asyncio
async def test_select_user(pg_base_config):
    # Arrange
    uc1 = UserContext(subject_id="user1", issuer_id="https://test-cactus-issuer.example.com")
    uc2 = UserContext(subject_id="user2", issuer_id="https://test-cactus-issuer.example.com")

    # Act
    async with generate_async_session(pg_base_config) as session:
        user1 = await select_user(session, uc1)
        user2 = await select_user(session, uc2)

        # Assert
        assert user1 is not None
        assert user2 is not None


@pytest.mark.asyncio
async def test_select_user_missing(pg_base_config):

    async with generate_async_session(pg_base_config) as session:
        assert (await select_user(session, UserContext(subject_id="user1", issuer_id="bad-issuer"))) is None
        assert (await select_user(session, UserContext(subject_id="", issuer_id=""))) is None
        assert (await select_user(session, UserContext(subject_id="dne", issuer_id="dne"))) is None


@pytest.mark.asyncio
async def test_select_group_runs_aggregated_by_procedure(pg_base_config):
    # We are going to clear out the runs and rework them for this test
    async with generate_async_session(pg_base_config) as session:
        await session.execute(delete(Run))

        runs = [
            Run(run_group_id=1, teststack_id="", testprocedure_id="NOT-A-TEST", run_status=1, all_criteria_met=True),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-01", run_status=1, all_criteria_met=True),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-01", run_status=1, all_criteria_met=False),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-02", run_status=1, all_criteria_met=None),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-03", run_status=1, all_criteria_met=True),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-04", run_status=1, all_criteria_met=None),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-04", run_status=1, all_criteria_met=True),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-05", run_status=1, all_criteria_met=True),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-05", run_status=1, all_criteria_met=True),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-06", run_status=1, all_criteria_met=True),
            Run(run_group_id=1, teststack_id="", testprocedure_id="ALL-06", run_status=1, all_criteria_met=None),
            Run(run_group_id=2, teststack_id="", testprocedure_id="ALL-01", run_status=1, all_criteria_met=False),
            Run(run_group_id=2, teststack_id="", testprocedure_id="ALL-01", run_status=1, all_criteria_met=None),
            Run(run_group_id=2, teststack_id="", testprocedure_id="ALL-01", run_status=1, all_criteria_met=True),
        ]
        session.add_all(runs)
        await session.commit()

    # Act
    async with generate_async_session(pg_base_config) as session:
        group_1_result = await select_group_runs_aggregated_by_procedure(session, 1)
        assert_list_type(ProcedureRunAggregated, group_1_result, len(TestProcedureId))
        assert ProcedureRunAggregated(TestProcedureId.ALL_01, 2, False) in group_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_02, 1, None) in group_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_03, 1, True) in group_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_04, 2, True) in group_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_05, 2, True) in group_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_06, 2, None) in group_1_result
        assert ProcedureRunAggregated(TestProcedureId.GEN_01, 0, None) in group_1_result

        group_2_result = await select_group_runs_aggregated_by_procedure(session, 2)
        assert_list_type(ProcedureRunAggregated, group_2_result, len(TestProcedureId))
        assert ProcedureRunAggregated(TestProcedureId.ALL_01, 3, True) in group_2_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_02, 0, None) in group_2_result

        group_3_result = await select_group_runs_aggregated_by_procedure(session, 3)
        assert_list_type(ProcedureRunAggregated, group_3_result, len(TestProcedureId))
        assert ProcedureRunAggregated(TestProcedureId.ALL_01, 0, None) in group_3_result


@pytest.mark.parametrize(
    "run_group_id, test_procedure_id, expected_run_ids",
    [(1, "ALL-01", [2, 1]), (2, "ALL-01", [5]), (1, "ALL-02", [3]), (1, "ALL-01.yaml", []), (99, "ALL-01", [])],
)
@pytest.mark.asyncio
async def test_select_group_runs_for_procedure(
    pg_base_config, run_group_id: int, test_procedure_id: str, expected_run_ids: list[int]
):

    # Act
    async with generate_async_session(pg_base_config) as session:
        result = await select_group_runs_for_procedure(session, run_group_id, test_procedure_id)
        assert [run.run_id for run in result] == expected_run_ids
        assert_list_type(Run, result, len(expected_run_ids))
