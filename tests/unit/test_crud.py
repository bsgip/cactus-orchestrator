from datetime import datetime, timezone
from itertools import product

import pytest
from assertical.asserts.type import assert_list_type
from assertical.fixtures.postgres import generate_async_session
from cactus_test_definitions.test_procedures import TestProcedureId
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from cactus_orchestrator.crud import (
    ProcedureRunAggregated,
    insert_run_for_user,
    insert_user,
    select_nonfinalised_runs,
    select_user,
    select_user_run,
    select_user_run_with_artifact,
    select_user_runs,
    select_user_runs_aggregated_by_procedure,
    select_user_runs_for_procedure,
    update_run_run_status,
    update_run_with_runartifact_and_finalise,
)
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.model import Run, RunStatus
from cactus_orchestrator.schema import UserContext


@pytest.mark.asyncio
async def test_insert_user(pg_empty_conn):
    """Tests that a new user can be inserted and that rollback/commit interact with it as expected"""
    # Arrange
    uc1 = UserContext(subject_id="sub1", issuer_id="issuer1")
    uc2 = UserContext(subject_id="sub2", issuer_id="issuer2")

    # Act
    async with generate_async_session(pg_empty_conn.connection) as s:
        user1 = await insert_user(s, uc1)

        assert user1.user_id == 1
        assert user1.aggregator_certificate_p12_bundle is None
        assert user1.aggregator_certificate_x509_der is None
        assert user1.device_certificate_p12_bundle is None
        assert user1.device_certificate_x509_der is None
        assert user1.subscription_domain is None
        assert isinstance(user1.is_static_uri, bool)
        assert user1.subject_id == uc1.subject_id
        assert user1.issuer_id == uc1.issuer_id

        await s.commit()

    # Test we can rollback
    async with generate_async_session(pg_empty_conn.connection) as s:
        user2 = await insert_user(s, uc2)

        assert user2.user_id == 2
        assert user2.aggregator_certificate_p12_bundle is None
        assert user2.aggregator_certificate_x509_der is None
        assert user2.device_certificate_p12_bundle is None
        assert user2.device_certificate_x509_der is None
        assert user2.subscription_domain is None
        assert isinstance(user2.is_static_uri, bool)
        assert user2.subject_id == uc2.subject_id
        assert user2.issuer_id == uc2.issuer_id

        await s.rollback()

    async with generate_async_session(pg_empty_conn.connection) as s:
        with pytest.raises(IntegrityError):
            await insert_user(s, uc1)

    # Test we can insert as expected
    async with generate_async_session(pg_empty_conn.connection) as s:
        user3 = await insert_user(s, uc2)

        assert user3.user_id == 4, "The sequence would have been incremented for the above two insert attempts"
        assert user3.aggregator_certificate_p12_bundle is None
        assert user3.aggregator_certificate_x509_der is None
        assert user3.device_certificate_p12_bundle is None
        assert user3.device_certificate_x509_der is None
        assert user3.subscription_domain is None
        assert isinstance(user3.is_static_uri, bool)
        assert user3.subject_id == uc2.subject_id
        assert user3.issuer_id == uc2.issuer_id

        await s.commit()


@pytest.mark.asyncio
async def test_add_or_update_user_unique_constraint(pg_empty_conn):
    """test exception raised on unique constraint breach"""
    # Arrange
    uc = UserContext(subject_id="a", issuer_id="a")

    async with generate_async_session(pg_empty_conn.connection) as s:
        _ = await insert_user(s, uc)
        await s.commit()

    with pytest.raises(IntegrityError):
        async with generate_async_session(pg_empty_conn.connection) as s:
            _ = await insert_user(s, uc)
            await s.commit()


@pytest.mark.asyncio
async def test_select_user_runs_all(pg_empty_conn):
    """Test fetching all runs for a user (no filters)."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
                INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO run (user_id, teststack_id, testprocedure_id, finalised_at, run_status)
            VALUES (
                1, 'teststack1', 'testproc1', NULL, 1
            ),
            (
                1, 'teststack2', 'testproc1', NOW(), 2
            ),
            (
                1, 'teststack3', 'testproc1', NOW(), 3
            ),
            (
                1, 'teststack4', 'testproc1', NOW(), 4
            ),
            (
                1, 'teststack5', 'testproc1', NOW(), 5
            )
        """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:

        runs = await select_user_runs(session, 1, finalised=None, created_at_gte=None)

    # Assert
    assert len(runs) == 5


@pytest.mark.parametrize(
    "run_status",
    [(RunStatus.finalised_by_client.value), (RunStatus.finalised_by_timeout.value)],
)
@pytest.mark.asyncio
async def test_select_user_runs_finalised_only(pg_empty_conn, run_status):
    """Test fetching only finalised runs."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
                INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            f"""
            INSERT INTO run (user_id, teststack_id, testprocedure_id, finalised_at, run_status)
            VALUES (
                1, 'teststack1', 'testproc1', NULL, 1
            ),
            (
                1, 'teststack2', 'testproc1', NOW(), {run_status}
            )
        """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        runs = await select_user_runs(session, 1, finalised=True, created_at_gte=None)

    # Assert
    assert len(runs) == 1
    assert runs[0].finalised_at is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("run_status", [(RunStatus.initialised.value), (RunStatus.started.value)])
async def test_select_user_runs_unfinalised_only(pg_empty_conn, run_status):
    """Test fetching only unfinalised runs."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
                INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            f"""
            INSERT INTO run (user_id, teststack_id, testprocedure_id, finalised_at, run_status)
            VALUES (
                1, 'teststack1', 'testproc1', NULL, {run_status}
            ),
            (
                1, 'teststack2', 'testproc1', NOW(), 4
            )
        """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:

        runs = await select_user_runs(session, 1, finalised=False, created_at_gte=None)

    # Assert
    assert len(runs) == 1
    assert runs[0].finalised_at is None


@pytest.mark.asyncio
async def test_select_user_runs_created_at_filter(pg_empty_conn):
    """Test filtering runs by creation date."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
                INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x')
            """
        )
    )
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO run (user_id, teststack_id, testprocedure_id, created_at, run_status)
            VALUES (
                1, 'teststack1', 'testproc1', '2024-01-01T00:00:00+00:00', 0
            ),
            (
                1, 'teststack2', 'testproc1', '2024-01-02T00:00:00+00:00', 0
            )
        """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:

        runs = await select_user_runs(
            session, 1, finalised=None, created_at_gte=datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        )

    # Assert
    assert len(runs) == 1


@pytest.mark.asyncio
async def test_insert_run_for_user(pg_empty_conn):
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x')
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        run_id = await insert_run_for_user(session, 1, "teststack1", "ALL_01", RunStatus.initialised, True)
        await session.commit()

    # Assert
    assert run_id is not None
    result = pg_empty_conn.execute(text("SELECT COUNT(*) FROM run")).fetchone()
    assert result[0] == 1


@pytest.mark.parametrize("run_status", [(RunStatus.initialised.value), (RunStatus.started.value)])
@pytest.mark.asyncio
async def test_select_nonfinalised_runs(pg_empty_conn, run_status):
    """Test selecting only non-finalised runs."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            f"""
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status)
            VALUES (1, 'teststack1', 'testproc1', {run_status}),
                   (1, 'teststack2', 'testproc1', 4)
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        runs = await select_nonfinalised_runs(session)

    # Assert
    assert len(runs) == 1
    assert runs[0].run_status == run_status


@pytest.mark.asyncio
async def test_update_run_run_status(pg_empty_conn):
    """Test updating the finalisation status of a run."""
    # Arrange
    finalised_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status)
            VALUES (1, 'teststack1', 'testproc1', 0)
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        await update_run_run_status(session, 1, 1, finalised_at)
        await session.commit()

    # Assert
    result = pg_empty_conn.execute(text("SELECT run_status, finalised_at FROM run")).fetchone()
    assert result[0] == 1
    assert result[1] is not None


@pytest.mark.asyncio
async def test_select_user_run(pg_empty_conn):
    """Test selecting a run for a given user."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status)
            VALUES (1, 'teststack1', 'testproc1', 0)
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        run = await select_user_run(session, 1, 1)

    # Assert
    assert run is not None
    assert run.user_id == 1
    assert run.run_id == 1


@pytest.mark.parametrize(
    "run_status, finalised_at, all_criteria_met",
    [
        (RunStatus.finalised_by_client, datetime(2025, 1, 1, tzinfo=timezone.utc), True),
        (RunStatus.finalised_by_timeout, datetime(2025, 2, 2, tzinfo=timezone.utc), False),
        (RunStatus.finalised_by_client, datetime(2025, 3, 3, tzinfo=timezone.utc), None),
    ],
)
@pytest.mark.asyncio
async def test_update_run_with_runartifact_and_finalise(pg_empty_conn, run_status, finalised_at, all_criteria_met):
    """Test updating a run with a run artifact and finalisation status."""
    # Arrange
    run = Run(user_id=1, teststack_id="teststack1", testprocedure_id="ALL01", run_status=0)
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            f"""
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status)
            VALUES ({run.user_id}, '{run.teststack_id}', '{run.testprocedure_id}', {run.run_status})
            """
        )
    )
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO run_artifact (compression, file_data)
            VALUES ('gzip', E'\\x');
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        run = await select_user_run(session, 1, 1)
        await update_run_with_runartifact_and_finalise(session, run, 1, run_status, finalised_at, all_criteria_met)
        await session.commit()

    # Assert
    result = pg_empty_conn.execute(
        text("SELECT run_artifact_id, run_status, finalised_at, all_criteria_met FROM run")
    ).fetchone()
    assert result[0] == 1
    assert result[1] == run_status.value
    assert result[2] == finalised_at
    assert result[3] == all_criteria_met


@pytest.mark.asyncio
async def test_select_user_run_with_artifact(pg_empty_conn):
    """Test selecting run with run artifact joined in load."""
    # Arrange
    run = Run(user_id=1, teststack_id="teststack1", testprocedure_id="ALL01", run_status=0)
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO run_artifact (compression, file_data)
            VALUES ('gzip', E'\\x');
            """
        )
    )
    pg_empty_conn.execute(
        text(
            f"""
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, run_artifact_id)
            VALUES ({run.user_id}, '{run.teststack_id}', '{run.testprocedure_id}', {run.run_status}, 1)
            """
        )
    )

    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        run = await select_user_run_with_artifact(session, 1, 1)

    # Assert
    assert run.run_artifact.run_artifact_id == 1
    assert run.run_artifact.compression == "gzip"


@pytest.mark.parametrize(
    "with_aggregator_der, with_aggregator_p12, with_device_der, with_device_p12",
    [(True, True, True, True), (False, False, False, False), (True, False, True, False), (False, True, False, True)],
)
@pytest.mark.asyncio
async def test_select_user(
    pg_empty_conn, with_aggregator_der: bool, with_aggregator_p12: bool, with_device_der: bool, with_device_p12: bool
):
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x01', E'\\x02', E'\\x03', E'\\x04');

            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user2', 'issuer2', NULL, NULL, NULL, NULL);
            """
        )
    )
    pg_empty_conn.commit()
    uc1 = UserContext(subject_id="user1", issuer_id="issuer1")
    uc2 = UserContext(subject_id="user2", issuer_id="issuer2")

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        user1 = await select_user(
            session, uc1, with_aggregator_der, with_aggregator_p12, with_device_der, with_device_p12
        )

        user2 = await select_user(
            session, uc2, with_aggregator_der, with_aggregator_p12, with_device_der, with_device_p12
        )

        # Assert
        assert user1 is not None
        assert user2 is not None
        if with_aggregator_p12:
            assert user1.aggregator_certificate_p12_bundle == bytes([1])
            assert user2.aggregator_certificate_p12_bundle is None
        else:
            with pytest.raises(Exception):
                user1.aggregator_certificate_p12_bundle
            with pytest.raises(Exception):
                user2.aggregator_certificate_p12_bundle

        if with_aggregator_der:
            assert user1.aggregator_certificate_x509_der == bytes([2])
            assert user2.aggregator_certificate_x509_der is None
        else:
            with pytest.raises(Exception):
                user1.aggregator_certificate_x509_der
            with pytest.raises(Exception):
                user2.aggregator_certificate_x509_der

        if with_device_p12:
            assert user1.device_certificate_p12_bundle == bytes([3])
            assert user2.device_certificate_p12_bundle is None
        else:
            with pytest.raises(Exception):
                user1.device_certificate_p12_bundle
            with pytest.raises(Exception):
                user2.device_certificate_p12_bundle

        if with_device_der:
            assert user1.device_certificate_x509_der == bytes([4])
            assert user2.device_certificate_x509_der is None
        else:
            with pytest.raises(Exception):
                user1.device_certificate_x509_der
            with pytest.raises(Exception):
                user2.device_certificate_x509_der


@pytest.mark.asyncio
async def test_select_user_missing(pg_empty_conn):
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x01', E'\\x02', E'\\x03', E'\\x04');

            INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES ('user2', 'issuer2', NULL, NULL, NULL, NULL);
            """
        )
    )
    pg_empty_conn.commit()

    async with generate_async_session(pg_empty_conn.connection) as session:
        assert (await select_user(session, UserContext(subject_id="user1", issuer_id="issuer2"))) is None
        assert (await select_user(session, UserContext(subject_id="user2", issuer_id="issuer1"))) is None
        assert (await select_user(session, UserContext(subject_id="", issuer_id=""))) is None
        assert (await select_user(session, UserContext(subject_id="dne", issuer_id="dne"))) is None


@pytest.mark.asyncio
async def test_select_user_runs_aggregated_by_procedure(pg_empty_conn):
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (id, subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES (1, 'user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            INSERT INTO user_ (id, subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES (2, 'user2', 'issuer2', E'\\x', E'\\x', E'\\x', E'\\x');

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'NOT-A-TEST-ID', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-01', 1, true);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-01', 1, false);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-02', 1, NULL);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-03', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-04', 1, NULL);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-04', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-05', 1, true);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-05', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-06', 1, true);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-06', 1, NULL);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (2, '', 'ALL-01', 1, false);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (2, '', 'ALL-01', 1, NULL);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (2, '', 'ALL-01', 1, true);
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        user_1_result = await select_user_runs_aggregated_by_procedure(session, 1)
        assert_list_type(ProcedureRunAggregated, user_1_result, len(TestProcedureId))
        assert ProcedureRunAggregated(TestProcedureId.ALL_01, 2, False) in user_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_02, 1, None) in user_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_03, 1, True) in user_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_04, 2, True) in user_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_05, 2, True) in user_1_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_06, 2, None) in user_1_result
        assert ProcedureRunAggregated(TestProcedureId.GEN_01, 0, None) in user_1_result

        user_2_result = await select_user_runs_aggregated_by_procedure(session, 2)
        assert_list_type(ProcedureRunAggregated, user_2_result, len(TestProcedureId))
        assert ProcedureRunAggregated(TestProcedureId.ALL_01, 3, True) in user_2_result
        assert ProcedureRunAggregated(TestProcedureId.ALL_02, 0, None) in user_2_result

        user_3_result = await select_user_runs_aggregated_by_procedure(session, 3)
        assert_list_type(ProcedureRunAggregated, user_3_result, len(TestProcedureId))
        assert ProcedureRunAggregated(TestProcedureId.ALL_01, 0, None) in user_3_result


@pytest.mark.asyncio
async def test_select_user_runs_for_procedure(pg_empty_conn):
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (id, subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES (1, 'user1', 'issuer1', E'\\x', E'\\x', E'\\x', E'\\x');
            INSERT INTO user_ (id, subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
            VALUES (2, 'user2', 'issuer2', E'\\x', E'\\x', E'\\x', E'\\x');

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'NOT-A-TEST-ID', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-01', 1, true);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-01', 1, false);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-02', 1, NULL);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-03', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-04', 1, NULL);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-04', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-05', 1, true);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-05', 1, true);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-06', 1, true);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (1, '', 'ALL-06', 1, NULL);

            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (2, '', 'ALL-01', 1, false);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (2, '', 'ALL-01', 1, NULL);
            INSERT INTO run (user_id, teststack_id, testprocedure_id, run_status, all_criteria_met)
            VALUES (2, '', 'ALL-01', 1, true);
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        all01_1_result = await select_user_runs_for_procedure(session, 1, "ALL-01")
        assert_list_type(Run, all01_1_result, 2)
        assert [run.run_id for run in all01_1_result] == [3, 2]

        all02_1_result = await select_user_runs_for_procedure(session, 1, "ALL-02")
        assert_list_type(Run, all02_1_result, 1)
        assert [run.run_id for run in all02_1_result] == [4]

        all01_2_result = await select_user_runs_for_procedure(session, 2, "ALL-01")
        assert_list_type(Run, all01_2_result, 3)
        assert [run.run_id for run in all01_2_result] == [14, 13, 12]

        all01_3_result = await select_user_runs_for_procedure(session, 3, "ALL-01")
        assert_list_type(Run, all01_3_result, 0)

        all01yaml_1_result = await select_user_runs_for_procedure(session, 1, "ALL-01.yaml")
        assert_list_type(Run, all01yaml_1_result, 0)
