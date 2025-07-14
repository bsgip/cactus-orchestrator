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
    upsert_user,
)
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.model import Run, RunStatus
from cactus_orchestrator.schema import UserContext


@pytest.mark.asyncio
async def test_add_user(pg_empty_conn, ca_cert_key_pair):
    """basic success test"""
    # Arrange
    ca_cert, ca_key = ca_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    uc = UserContext(subject_id="a", issuer_id="a")

    # Act
    async with generate_async_session(pg_empty_conn.connection) as s:
        user = await insert_user(s, uc, cl_p12, cl_der)

    # Assert
    assert user.user_id == 1
    assert user.certificate_p12_bundle == cl_p12
    assert user.certificate_x509_der == cl_der
    assert user.subject_id == uc.subject_id
    assert user.issuer_id == uc.issuer_id


@pytest.mark.asyncio
async def test_add_or_update_user_unique_constraint(pg_empty_conn, ca_cert_key_pair):
    """test exception raised on unique constraint breach"""
    # Arrange
    ca_cert, ca_key = ca_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    uc = UserContext(subject_id="a", issuer_id="a")

    async with generate_async_session(pg_empty_conn.connection) as s:
        _ = await insert_user(s, uc, cl_p12, cl_der)
        await s.commit()

    with pytest.raises(IntegrityError):
        async with generate_async_session(pg_empty_conn.connection) as s:
            _ = await insert_user(s, uc, cl_p12, cl_der)
            await s.commit()


@pytest.mark.asyncio
async def test_add_or_update_user(pg_empty_conn, ca_cert_key_pair):
    """Create a user, then update their certs"""
    # Arrange
    ca_cert, ca_key = ca_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    uc = UserContext(subject_id="a", issuer_id="a")

    async with generate_async_session(pg_empty_conn.connection) as s:
        _ = await insert_user(s, uc, cl_p12, cl_der)
        await s.commit()

    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test1", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    # Act
    async with generate_async_session(pg_empty_conn.connection) as s:
        await upsert_user(s, uc, cl_p12, cl_der)
        await s.commit()
    # Assert
    cert_x509_der = pg_empty_conn.execute(text("select certificate_x509_der from user_;")).fetchone()[0]
    cert_x509 = x509.load_der_x509_certificate(cert_x509_der)
    assert cert_x509.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "test1"


@pytest.mark.asyncio
async def test_select_user_runs_all(pg_empty_conn):
    """Test fetching all runs for a user (no filters)."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
                INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
                INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
                INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
                INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
                VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
            """
        )
    )
    pg_empty_conn.commit()

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        run_id = await insert_run_for_user(session, 1, "teststack1", "ALL_01", RunStatus.initialised)
        await session.commit()

    # Assert
    assert run_id is not None
    result = pg_empty_conn.execute(text(f"SELECT COUNT(*) FROM run")).fetchone()
    assert result[0] == 1


@pytest.mark.parametrize("run_status", [(RunStatus.initialised.value), (RunStatus.started.value)])
@pytest.mark.asyncio
async def test_select_nonfinalised_runs(pg_empty_conn, run_status):
    """Test selecting only non-finalised runs."""
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
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


@pytest.mark.parametrize(("with_der", "with_p12"), product((True, False), (True, False)))
@pytest.mark.asyncio
async def test_select_user(pg_empty_conn, with_der: bool, with_p12: bool):
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES ('user1', 'issuer1', E'\\x', E'\\x')
            """
        )
    )
    pg_empty_conn.commit()
    uc = UserContext(subject_id="user1", issuer_id="issuer1")

    # Act
    async with generate_async_session(pg_empty_conn.connection) as session:
        user = await select_user(session, uc, with_der, with_p12)

        # Assert
        assert user is not None
        if with_der:
            assert user.certificate_x509_der is not None
        else:
            with pytest.raises(Exception):
                user.certificate_x509_der

        if with_p12:
            assert user.certificate_p12_bundle is not None
        else:
            with pytest.raises(Exception):
                user.certificate_p12_bundle


@pytest.mark.asyncio
async def test_select_user_runs_aggregated_by_procedure(pg_empty_conn):
    # Arrange
    pg_empty_conn.execute(
        text(
            """
            INSERT INTO user_ (id, subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES (1, 'user1', 'issuer1', E'\\x', E'\\x');
            INSERT INTO user_ (id, subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES (2, 'user2', 'issuer2', E'\\x', E'\\x');

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
            INSERT INTO user_ (id, subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES (1, 'user1', 'issuer1', E'\\x', E'\\x');
            INSERT INTO user_ (id, subject_id, issuer_id, certificate_p12_bundle, certificate_x509_der)
            VALUES (2, 'user2', 'issuer2', E'\\x', E'\\x');

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
