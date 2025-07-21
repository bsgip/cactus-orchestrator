import os
from datetime import datetime, timezone
from http import HTTPMethod, HTTPStatus
from typing import Generator
from unittest.mock import AsyncMock, Mock, patch

import pytest
from assertical.fake.generator import generate_class_instance
from assertical.fake.sqlalchemy import assert_mock_session, create_mock_session
from cactus_runner.models import CriteriaEntry, RequestEntry, RunnerStatus
from cactus_test_definitions import TestProcedureId
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from fastapi_pagination import Params, set_params
from sqlalchemy.exc import NoResultFound

from cactus_orchestrator.api.certificate import _ca_crt_cachekey, update_ca_certificate_cache
from cactus_orchestrator.api.run import finalise_run, is_all_criteria_met, teardown_teststack
from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.crud import ProcedureRunAggregated
from cactus_orchestrator.k8s.run_id import generate_envoy_dcap_uri, generate_static_test_stack_id
from cactus_orchestrator.main import app
from cactus_orchestrator.model import Run, RunArtifact, RunStatus, User
from cactus_orchestrator.schema import (
    InitRunRequest,
    InitRunResponse,
    RunResponse,
    StartRunResponse,
    TestProcedureResponse,
    TestProcedureRunSummaryResponse,
    UserConfigurationRequest,
)
from cactus_orchestrator.settings import CactusOrchestratorException


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    yield TestClient(app)


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_user=AsyncMock(),
    select_user_runs=AsyncMock(),
    update_run_run_status=AsyncMock(),
)
def test_post_spawn_test_created(client, valid_user_p12_and_der, valid_user_jwt):
    """Just a simple test, with all k8s functions stubbed, to catch anything silly in the handler"""
    # Arrange
    from cactus_orchestrator.api.run import (
        RunnerClient,
        clone_statefulset,
        insert_run_for_user,
        select_user,
        select_user_runs,
        update_run_run_status,
    )

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=valid_user_p12_and_der[1],
        is_static_uri=False,
    )
    RunnerClient.init = AsyncMock()
    clone_statefulset.return_value = "pod_name"
    insert_run_for_user.return_value = 1
    select_user_runs.return_value = []

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    resmdl = InitRunResponse.model_validate(res.json())
    assert os.environ["TEST_EXECUTION_FQDN"] in resmdl.test_url
    assert res.headers["Location"] == "/run/1"
    insert_run_for_user.assert_called_once()
    update_run_run_status.assert_called_once()
    select_user_runs.assert_not_called()  # This isn't a static_uri test so we shouldn't be checking


@patch.multiple(
    "cactus_orchestrator.api.run",
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_user=AsyncMock(),
    select_user_runs=AsyncMock(),
    update_run_run_status=AsyncMock(),
)
def test_post_spawn_test_expired_cert(client, expired_user_p12_and_der, valid_user_jwt):
    """An expired cert should NOT start any services"""
    # Arrange
    from cactus_orchestrator.api.run import (
        clone_statefulset,
        insert_run_for_user,
        select_user,
        select_user_runs,
        update_run_run_status,
    )

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=expired_user_p12_and_der[1],
        is_static_uri=False,
    )

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.EXPECTATION_FAILED

    insert_run_for_user.assert_not_called()
    update_run_run_status.assert_not_called()
    select_user_runs.assert_not_called()
    clone_statefulset.assert_not_called()


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_user=AsyncMock(),
    select_user_runs=AsyncMock(),
    update_run_run_status=AsyncMock(),
)
def test_post_spawn_test_created_static_uri(client, valid_user_p12_and_der, valid_user_jwt):
    """Just a simple test, with all k8s functions stubbed, to catch anything silly in the handler"""
    # Arrange
    from cactus_orchestrator.api.run import (
        RunnerClient,
        clone_statefulset,
        insert_run_for_user,
        select_user,
        select_user_runs,
        update_run_run_status,
    )

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=valid_user_p12_and_der[1],
        is_static_uri=True,
    )
    RunnerClient.init = AsyncMock()
    clone_statefulset.return_value = "pod_name"
    insert_run_for_user.return_value = 1
    select_user_runs.return_value = []  # no existing runs

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    resmdl = InitRunResponse.model_validate(res.json())
    assert os.environ["TEST_EXECUTION_FQDN"] in resmdl.test_url
    assert res.headers["Location"] == "/run/1"
    insert_run_for_user.assert_called_once()
    update_run_run_status.assert_called_once()
    select_user_runs.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_user=AsyncMock(),
    select_user_runs=AsyncMock(),
    update_run_run_status=AsyncMock(),
)
def test_post_spawn_test_created_static_uri_existing_run(client, valid_user_p12_and_der, valid_user_jwt):
    """Attempting to spawn a test run with an existing run (if this is a static URI user) should raise an error"""
    # Arrange
    from cactus_orchestrator.api.run import (
        RunnerClient,
        clone_statefulset,
        insert_run_for_user,
        select_user,
        select_user_runs,
        update_run_run_status,
    )

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=valid_user_p12_and_der[1],
        is_static_uri=True,
    )
    RunnerClient.init = AsyncMock()
    clone_statefulset.return_value = "pod_name"
    insert_run_for_user.return_value = 1
    select_user_runs.return_value = [generate_class_instance(Run)]  # an existing run - should cause CONFLICT error

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CONFLICT
    insert_run_for_user.assert_not_called()
    select_user_runs.assert_called_once()
    update_run_run_status.assert_not_called()


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    select_user=AsyncMock(),
    select_user_run=AsyncMock(),
    update_run_run_status=AsyncMock(),
)
@patch("cactus_orchestrator.api.run.db")
def test_start_run(mock_db, client, valid_user_p12_and_der, valid_user_jwt):
    """Just a simple test, with all k8s functions stubbed, to catch anything silly in the handler"""
    # Arrange
    from cactus_orchestrator.api.run import RunnerClient, select_user, select_user_run, update_run_run_status

    mock_db_session = create_mock_session()
    mock_db.session = mock_db_session

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=valid_user_p12_and_der[1],
    )
    RunnerClient.start = AsyncMock()
    select_user_run.return_value = Run(
        run_id=1,
        user_id=1,
        teststack_id="abc",
        testprocedure_id=1,
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        run_status=0.0,
    )

    # Act
    res = client.post("run/1", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert_mock_session(mock_db_session, committed=True)
    assert res.status_code == HTTPStatus.OK
    resmdl = StartRunResponse.model_validate(res.json())
    assert os.environ["TEST_EXECUTION_FQDN"] in resmdl.test_url
    update_run_run_status.assert_awaited_once()
    assert update_run_run_status.call_args.kwargs["run_status"] == RunStatus.started


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    teardown_teststack=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_user=AsyncMock(),
    update_run_run_status=AsyncMock(),
)
def test_post_spawn_test_teardown_on_failure(client, valid_user_jwt, valid_user_p12_and_der):
    """Asserts teardown is triggered on spawn failure"""
    # Arrange
    from cactus_orchestrator.api.run import (
        clone_statefulset,
        insert_run_for_user,
        select_user,
        teardown_teststack,
        update_run_run_status,
    )

    clone_statefulset.side_effect = CactusOrchestratorException("fail")
    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=valid_user_p12_and_der[1],
    )

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    teardown_teststack.assert_called_once()
    insert_run_for_user.assert_called_once()
    update_run_run_status.assert_not_called()


@patch.multiple(
    "cactus_orchestrator.api.certificate",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=Mock(),
    upsert_user=AsyncMock(return_value=1),
)
def test_create_new_certificate(client, valid_user_jwt, ca_cert_key_pair):
    """Test creating a new certificate for a user"""
    # Arrange
    from cactus_orchestrator.api.certificate import fetch_certificate_key_pair, generate_client_p12

    mock_p12 = b"mock_p12_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes.return_value = b"mock_cert_data"

    generate_client_p12.return_value = (mock_p12, mock_cert)
    fetch_certificate_key_pair.return_value = ca_cert_key_pair

    # Act
    res = client.put("/certificate", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content == b"mock_p12_data"
    assert res.headers["content-type"] == "application/x-pkcs12"


@patch("cactus_orchestrator.api.certificate.select_user")
def test_fetch_existing_certificate(mock_select_user, client, valid_user_jwt):
    # Arrange
    mock_select_user.return_value = User(certificate_p12_bundle=b"mock_p12_data")

    # Act
    res = client.get("/certificate", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content == b"mock_p12_data"
    assert res.headers["content-type"] == "application/x-pkcs12"


@patch("cactus_orchestrator.api.certificate.select_user")
def test_fetch_existing_certificate_notfound(mock_select_user, client, valid_user_jwt):
    # Arrange
    mock_select_user.return_value = None

    # Act
    res = client.get("/certificate", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND


# NOTE: not api route handler, Controller/Managment layer
@patch("cactus_orchestrator.api.certificate.fetch_certificate_only", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_update_ca_certificate_cache(mock_fetch_certificate_only, ca_cert_key_pair):
    """basic success test for cache update function"""
    # Arrange
    mock_fetch_certificate_only.return_value = ca_cert_key_pair[0]

    # Act
    res = await update_ca_certificate_cache(None)

    # Assert
    assert isinstance(res[_ca_crt_cachekey], ExpiringValue)
    assert res[_ca_crt_cachekey].expiry == ca_cert_key_pair[0].not_valid_after_utc


@patch("cactus_orchestrator.api.certificate._ca_crt_cache", spec=AsyncCache)
def test_fetch_current_certificate_authority_der(mock_ca_crt_cache, client, ca_cert_key_pair, valid_user_jwt):
    """Basic success path test."""
    # Arrange
    mock_ca_crt_cache.get_value = AsyncMock(return_value=ca_cert_key_pair[0])

    # Act
    res = client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.headers["content-type"] == "application/x-x509-ca-cert"
    assert res.content == ca_cert_key_pair[0].public_bytes(serialization.Encoding.DER)


@patch("cactus_orchestrator.api.procedure.test_procedure_responses", [])
def test_get_test_procedure_list_empty(client, valid_user_jwt):
    """Test when there are no test procedure available."""
    # Arrange
    set_params(Params(size=10, page=1))

    # Act
    res = client.get("/procedure", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.json()["total"] == 0
    assert res.json()["items"] == []


@patch(
    "cactus_orchestrator.api.procedure.test_procedure_responses",
    [
        TestProcedureResponse(
            test_procedure_id="ALL-01",
            category="a",
            description="blah",
        )
    ],
)
def test_get_test_procedure_list_populated(client, valid_user_jwt):
    """Test when there are test procedure available."""
    # Arrange
    set_params(Params(size=10, page=1))

    # Act
    res = client.get("/procedure", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["test_procedure_id"] == "ALL-01"


@pytest.mark.parametrize(
    "run_id, status", [("ALL-01", 200), ("LOA-02", 200), ("GEN-03", 200), ("../ALL-01", 404), ("./ALL-01.yaml", 404)]
)
def test_get_test_procedures_by_id(client, valid_user_jwt, run_id, status):
    """Test we can fetch individual test procedures by id"""
    # Arrange
    set_params(Params(size=10, page=1))

    # Act
    res = client.get(f"/procedure/{run_id}", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == status
    if status == 200:
        res.headers["Content-Type"] == "application/yaml"
        assert len(res.text) > 10


@patch.multiple(
    "cactus_orchestrator.api.procedure",
    select_user_or_raise=AsyncMock(),
    select_user_runs_aggregated_by_procedure=AsyncMock(),
)
def test_get_procedure_run_summaries(client, valid_user_jwt):
    """Test retrieving procedure run summaries"""
    from cactus_orchestrator.api.procedure import select_user_or_raise, select_user_runs_aggregated_by_procedure

    # Arrange
    set_params(Params(size=10, page=1))
    select_user_or_raise.return_value = User(user_id=1, subject_id="sub", issuer_id="iss")

    select_user_runs_aggregated_by_procedure.return_value = [
        ProcedureRunAggregated(TestProcedureId.LOA_08, 123, True),
        ProcedureRunAggregated(TestProcedureId.ALL_02, 0, None),
    ]

    # Act
    res = client.get("/procedure_runs", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 2

    items = [TestProcedureRunSummaryResponse.model_validate(d) for d in data]
    assert items[0].test_procedure_id == TestProcedureId.LOA_08
    assert items[0].run_count == 123
    assert items[0].latest_all_criteria_met is True
    assert len(items[0].category), "Should not be an empty string"
    assert len(items[0].description), "Should not be an empty string"

    assert items[1].test_procedure_id == TestProcedureId.ALL_02
    assert items[1].run_count == 0
    assert items[1].latest_all_criteria_met is None
    assert len(items[1].category), "Should not be an empty string"
    assert len(items[1].description), "Should not be an empty string"

    assert items[0].category != items[1].category
    assert items[0].description != items[1].description

    select_user_or_raise.assert_called_once()
    select_user_runs_aggregated_by_procedure.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.procedure",
    select_user_or_raise=AsyncMock(),
    select_user_runs_for_procedure=AsyncMock(),
)
def test_get_runs_for_procedure(client, valid_user_jwt):
    """Test retrieving paginated user runs (underneath a procedure)"""
    from cactus_orchestrator.api.procedure import select_user_or_raise, select_user_runs_for_procedure

    # Arrange
    set_params(Params(size=10, page=1))
    select_user_or_raise.return_value = User(user_id=1, subject_id="sub", issuer_id="iss")
    mock_run = Run(
        run_id=1,
        user_id=1,
        teststack_id="abc",
        testprocedure_id="ALL-01",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        finalised_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
        run_artifact_id=1,
        run_status=RunStatus.started,
    )
    select_user_runs_for_procedure.return_value = [mock_run]

    # Act
    res = client.get("/procedure_runs/ALL-01", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, dict)
    assert "items" in data
    assert len(data["items"]) == 1
    assert data["items"][0]["run_id"] == 1
    select_user_or_raise.assert_called_once()
    select_user_runs_for_procedure.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.run",
    select_user=AsyncMock(),
    select_user_runs=AsyncMock(),
)
def test_get_runs_paginated(client, valid_user_jwt):
    """Test retrieving paginated user runs"""
    from cactus_orchestrator.api.run import select_user, select_user_runs

    # Arrange
    set_params(Params(size=10, page=1))
    select_user.return_value = User(user_id=1, subject_id="sub", issuer_id="iss")
    mock_run = Run(
        run_id=1,
        user_id=1,
        teststack_id="abc",
        testprocedure_id="ALL-01",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        finalised_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
        run_artifact_id=1,
        run_status=RunStatus.started,
    )
    select_user_runs.return_value = [mock_run]

    params = {
        "finalised": True,
        "created_after": datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat(),
    }

    # Act
    res = client.get("/run", params=params, headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, dict)
    assert "items" in data
    assert len(data["items"]) == 1
    assert data["items"][0]["run_id"] == 1
    select_user.assert_called_once()
    select_user_runs.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.run",
    select_user=AsyncMock(),
    select_user_run=AsyncMock(),
)
def test_get_run_exists(client, valid_user_jwt):
    """Test retrieving paginated user runs"""
    from cactus_orchestrator.api.run import select_user, select_user_run

    # Arrange
    set_params(Params(size=10, page=1))
    select_user.return_value = User(user_id=1, subject_id="sub", issuer_id="iss")
    mock_run = Run(
        run_id=123,
        user_id=1,
        teststack_id="abc",
        testprocedure_id="ALL-01",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        finalised_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
        run_artifact_id=1,
        run_status=RunStatus.started,
        all_criteria_met=True,
    )
    select_user_run.return_value = mock_run

    params = {
        "finalised": True,
        "created_after": datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat(),
    }

    # Act
    res = client.get("/run/123", params=params, headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    run_response = RunResponse.model_validate_json(res.text)
    assert run_response.run_id == mock_run.run_id
    assert run_response.test_url
    assert run_response.all_criteria_met is mock_run.all_criteria_met
    assert run_response.created_at == mock_run.created_at
    assert run_response.finalised_at == mock_run.finalised_at
    select_user.assert_called_once()
    select_user_run.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.run",
    select_user=AsyncMock(),
    select_user_run=AsyncMock(),
)
def test_get_run_missing(client, valid_user_jwt):
    """Test retrieving paginated user runs"""
    from cactus_orchestrator.api.run import select_user, select_user_run

    # Arrange
    set_params(Params(size=10, page=1))
    select_user.return_value = User(user_id=1, subject_id="sub", issuer_id="iss")
    select_user_run.side_effect = NoResultFound()

    params = {
        "finalised": True,
        "created_after": datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat(),
    }

    # Act
    res = client.get("/run/123", params=params, headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND
    select_user.assert_called_once()
    select_user_run.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.remove_ingress_rule")
@patch("cactus_orchestrator.api.run.delete_service")
@patch("cactus_orchestrator.api.run.delete_statefulset")
async def test_teardown_teststack(mock_delete_statefulset, mock_delete_service, mock_remove_ingress_rule):
    # Act
    await teardown_teststack("test-service", "test-statefulset")

    # Assert
    mock_remove_ingress_rule.assert_called_once_with("test-service")
    mock_delete_service.assert_called_once_with("test-service")
    mock_delete_statefulset.assert_called_once_with("test-statefulset")


@pytest.mark.parametrize(
    "runner_status, expected",
    [
        (None, None),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(True, "", ""), CriteriaEntry(True, "", "")],
                request_history=[
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", []),
                    RequestEntry("", "", HTTPMethod.POST, HTTPStatus.OK, datetime.now(), "", None),
                ],
            ),
            True,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[],
                request_history=[],
            ),
            True,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=None,
                request_history=None,
            ),
            True,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(True, "", ""), CriteriaEntry(True, "", "")],
                request_history=[
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", None),
                    RequestEntry("", "", HTTPMethod.POST, HTTPStatus.OK, datetime.now(), "", ["validation error"]),
                ],
            ),
            False,
        ),  # validation error
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(True, "", ""), CriteriaEntry(False, "", "")],
                request_history=[
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", None),
                    RequestEntry("", "", HTTPMethod.POST, HTTPStatus.OK, datetime.now(), "", []),
                ],
            ),
            False,
        ),  # criteria error
    ],
)
def test_is_all_criteria_met(runner_status: RunnerStatus | None, expected: bool | None):
    actual = is_all_criteria_met(runner_status)
    assert actual is expected


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.is_all_criteria_met")
@patch("cactus_orchestrator.api.run.RunnerClient.status")
@patch("cactus_orchestrator.api.run.RunnerClient.finalize")
@patch("cactus_orchestrator.api.run.create_runartifact")
@patch("cactus_orchestrator.api.run.update_run_with_runartifact_and_finalise")
@patch("cactus_orchestrator.api.run.db")
async def test_finalise_run_creates_run_artifact_and_updates_run(
    mock_db,
    mock_update_run_with_runartifact_and_finalise,
    mock_create_runartifact,
    mock_finalize,
    mock_status,
    mock_is_all_criteria_met,
):
    # Arrange
    run_artifact = RunArtifact(run_artifact_id=1)
    runner_status = generate_class_instance(RunnerStatus, step_status={})
    mock_finalize.return_value = "file_data"  # TODO: this should be bytes, fix in client
    mock_status.return_value = runner_status
    mock_create_runartifact.return_value = run_artifact
    mock_is_all_criteria_met.return_value = True

    mock_db_session = create_mock_session()
    mock_db.session = mock_db_session

    # Act
    run = Run(teststack_id=1)
    result = await finalise_run(
        run, "http://mockurl", Mock(), RunStatus.finalised_by_client, datetime.now(timezone.utc)
    )

    # Assert
    assert result is run_artifact
    assert_mock_session(mock_db_session, committed=True)
    mock_is_all_criteria_met.assert_called_once_with(runner_status)
    mock_finalize.assert_called_once()
    mock_create_runartifact.assert_called_once()
    mock_update_run_with_runartifact_and_finalise.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.is_all_criteria_met")
@patch("cactus_orchestrator.api.run.RunnerClient.status")
@patch("cactus_orchestrator.api.run.RunnerClient.finalize")
@patch("cactus_orchestrator.api.run.create_runartifact")
@patch("cactus_orchestrator.api.run.update_run_with_runartifact_and_finalise")
@patch("cactus_orchestrator.api.run.db")
async def test_finalise_run_failure_to_finalize(
    mock_db,
    mock_update_run_with_runartifact_and_finalise,
    mock_create_runartifact,
    mock_finalize,
    mock_status,
    mock_is_all_criteria_met,
):
    """If the finalize "fails" but the test stack was still torn down - make sure we return None"""
    # Arrange
    runner_status = generate_class_instance(RunnerStatus, step_status={})
    mock_status.return_value = runner_status
    mock_finalize.side_effect = Exception("mock error during finalize")
    mock_create_runartifact.return_value = None  #
    mock_is_all_criteria_met.return_value = True

    mock_db_session = create_mock_session()
    mock_db.session = mock_db_session

    # Act
    run = Run(teststack_id=1)
    result = await finalise_run(
        run, "http://mockurl", Mock(), RunStatus.finalised_by_client, datetime.now(timezone.utc)
    )

    # Assert
    assert result is None
    assert_mock_session(mock_db_session, committed=True)
    mock_is_all_criteria_met.assert_called_once_with(runner_status)
    mock_finalize.assert_called_once()
    mock_create_runartifact.assert_not_called()
    mock_update_run_with_runartifact_and_finalise.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.is_all_criteria_met")
@patch("cactus_orchestrator.api.run.RunnerClient.status")
@patch("cactus_orchestrator.api.run.RunnerClient.finalize")
@patch("cactus_orchestrator.api.run.create_runartifact")
@patch("cactus_orchestrator.api.run.update_run_with_runartifact_and_finalise")
@patch("cactus_orchestrator.api.run.db")
async def test_finalise_run_creates_run_artifact_and_updates_run_status_error(
    mock_db,
    mock_update_run_with_runartifact_and_finalise,
    mock_create_runartifact,
    mock_finalize,
    mock_status,
    mock_is_all_criteria_met,
):
    """Tests that even if the status endpoint raises an error - we still proceed"""
    # Arrange
    mock_finalize.return_value = "file_data"  # TODO: this should be bytes, fix in client
    mock_status.side_effect = Exception("mock error during status fetch")
    mock_create_runartifact.return_value = RunArtifact(run_artifact_id=1)
    mock_is_all_criteria_met.return_value = True

    mock_db_session = create_mock_session()
    mock_db.session = mock_db_session

    # Act
    run = Run(teststack_id=1)
    await finalise_run(run, "http://mockurl", Mock(), RunStatus.finalised_by_client, datetime.now(timezone.utc))

    # Assert
    assert_mock_session(mock_db_session, committed=True)
    mock_is_all_criteria_met.assert_called_once_with(None)
    mock_finalize.assert_called_once()
    mock_create_runartifact.assert_called_once()
    mock_update_run_with_runartifact_and_finalise.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.select_user_or_raise")
@patch("cactus_orchestrator.api.run.select_user_run")
@patch("cactus_orchestrator.api.run.finalise_run")
@patch("cactus_orchestrator.api.run.teardown_teststack")
async def test_finalise_run_and_teardown_teststack_success(
    mock_teardown_teststack, mock_finalise_run, mock_select_user_run, mock_select_user_or_raise, client, valid_user_jwt
):
    # Arrange
    mock_select_user_or_raise.return_value = User(user_id=1)
    mock_select_user_run.return_value = Run(teststack_id=1)
    mock_finalise_run.return_value = RunArtifact(
        compression="gzip",
        file_data=b"\x1f\x8b\x08\x00I\xe9\xe4g\x02\xff\xcb,)N\xccM\xf5M,\xca\xcc\x07\x00\xcd\xcc5\xc5\x0b\x00\x00\x00",
    )

    # Act
    response = client.post("/run/1/finalise", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    mock_finalise_run.assert_called_once()
    mock_teardown_teststack.assert_called_once()
    assert response.status_code == 200


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.select_user_or_raise")
@patch("cactus_orchestrator.api.run.select_user_run")
@patch("cactus_orchestrator.api.run.finalise_run")
@patch("cactus_orchestrator.api.run.teardown_teststack")
async def test_finalise_run_and_teardown_teststack_failure_to_fetch_artifact(
    mock_teardown_teststack, mock_finalise_run, mock_select_user_run, mock_select_user_or_raise, client, valid_user_jwt
):
    """If the finalize artifact couldn't be fetched - return a HTTP NO_CONTENT"""
    # Arrange
    mock_select_user_or_raise.return_value = User(user_id=1)
    mock_select_user_run.return_value = Run(teststack_id=1)
    mock_finalise_run.return_value = None

    # Act
    response = client.post("/run/1/finalise", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    mock_finalise_run.assert_called_once()
    mock_teardown_teststack.assert_called_once()
    assert response.status_code == 204


@pytest.mark.parametrize("is_static_uri", [True, False])
@patch("cactus_orchestrator.api.config.select_user_or_raise")
def test_fetch_existing_config(mock_select_user_or_raise, client, valid_user_jwt, is_static_uri: bool):
    # Arrange
    domain = "my.custom.domain"
    user = User(subscription_domain=domain, is_static_uri=is_static_uri, user_id=123)
    mock_select_user_or_raise.return_value = user

    # Act
    res = client.get("/config", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["subscription_domain"] == domain
    assert data["is_static_uri"] is is_static_uri
    if is_static_uri:
        assert data["static_uri"] == generate_envoy_dcap_uri(generate_static_test_stack_id(user))
    else:
        assert data["static_uri"] is None


@pytest.mark.parametrize("is_static_uri", [True, False])
@patch("cactus_orchestrator.api.config.select_user_or_raise")
def test_fetch_existing_config_domain_none_value(
    mock_select_user_or_raise, client, valid_user_jwt, is_static_uri: bool
):
    # Arrange
    user = User(subscription_domain=None, is_static_uri=is_static_uri, user_id=123)
    mock_select_user_or_raise.return_value = user

    # Act
    res = client.get("/config", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["subscription_domain"] == ""
    assert data["is_static_uri"] is is_static_uri

    if is_static_uri:
        assert data["static_uri"] == generate_envoy_dcap_uri(generate_static_test_stack_id(user))
    else:
        assert data["static_uri"] is None


@pytest.mark.parametrize(
    "input_domain, input_is_static_uri, expected",
    [
        ("", True, ""),
        ("my.domain.example", True, "my.domain.example"),
        ("my.domain.example", False, "my.domain.example"),
        ("http://my.other.example:123/foo/bar", True, "my.other.example"),
        ("http://my.other.example:123/foo/bar", False, "my.other.example"),
        ("http://my.other.example2/", True, "my.other.example2"),
        ("http://my.other.example2/", False, "my.other.example2"),
    ],
)
@patch("cactus_orchestrator.api.config.select_user_or_raise")
def test_update_existing_config(
    mock_select_user_or_raise, client, valid_user_jwt, input_domain: str, input_is_static_uri: bool, expected: str
):
    # Arrange
    domain = "original.domain"
    user = User(subscription_domain=domain, is_static_uri=False)
    mock_select_user_or_raise.return_value = user

    # Act
    req = UserConfigurationRequest(subscription_domain=input_domain, is_static_uri=input_is_static_uri)
    res = client.post("/config", headers={"Authorization": f"Bearer {valid_user_jwt}"}, json=req.model_dump())

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    data = res.json()
    assert data["subscription_domain"] == expected
    assert data["is_static_uri"] == input_is_static_uri

    if input_is_static_uri:
        assert data["static_uri"] == generate_envoy_dcap_uri(generate_static_test_stack_id(user))
    else:
        assert data["static_uri"] is None


@pytest.mark.parametrize("runner_status", [RunStatus.initialised, RunStatus.started])
@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    select_user=AsyncMock(),
    select_user_run=AsyncMock(),
)
@patch("cactus_orchestrator.api.run.db")
def test_get_run_status(mock_db, client, valid_user_jwt, runner_status):
    """Does fetching the run status work under success conditions"""
    # Arrange
    from cactus_orchestrator.api.run import RunnerClient, select_user, select_user_run

    mock_db_session = create_mock_session()
    mock_db.session = mock_db_session

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=None,
    )
    expected_status = generate_class_instance(RunnerStatus, generate_relationships=True, step_status={})
    RunnerClient.status = AsyncMock(return_value=expected_status)
    select_user_run.return_value = Run(
        run_id=1,
        user_id=1,
        teststack_id="abc",
        testprocedure_id=1,
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        run_status=runner_status,
    )

    # Act
    res = client.get("run/1/status", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert_mock_session(mock_db_session)
    assert res.status_code == HTTPStatus.OK
    actual_status = RunnerStatus.from_dict(res.json())
    assert actual_status == expected_status


@pytest.mark.parametrize(
    "runner_status", [RunStatus.finalised_by_client, RunStatus.finalised_by_timeout, RunStatus.terminated]
)
@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    select_user=AsyncMock(),
    select_user_run=AsyncMock(),
)
@patch("cactus_orchestrator.api.run.db")
def test_get_run_status_bad_run_state(mock_db, client, valid_user_jwt, runner_status):
    """fetching the run status for a run that has finished should fail"""
    # Arrange
    from cactus_orchestrator.api.run import RunnerClient, select_user, select_user_run

    mock_db_session = create_mock_session()
    mock_db.session = mock_db_session

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=None,
    )
    expected_status = generate_class_instance(RunnerStatus, generate_relationships=True, step_status={})
    RunnerClient.status = AsyncMock(return_value=expected_status)
    select_user_run.return_value = Run(
        run_id=1,
        user_id=1,
        teststack_id="abc",
        testprocedure_id=1,
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        run_status=runner_status,
    )

    # Act
    res = client.get("run/1/status", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert_mock_session(mock_db_session)
    assert res.status_code == HTTPStatus.GONE


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    select_user=AsyncMock(),
    select_user_run=AsyncMock(),
)
@patch("cactus_orchestrator.api.run.db")
def test_get_run_status_missing_run(mock_db, client, valid_user_jwt):
    """fetching the run status for a run that has finished should fail"""
    # Arrange
    from cactus_orchestrator.api.run import RunnerClient, select_user, select_user_run

    mock_db_session = create_mock_session()
    mock_db.session = mock_db_session

    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        certificate_p12_bundle=None,
        certificate_x509_der=None,
    )
    expected_status = generate_class_instance(RunnerStatus, generate_relationships=True, step_status={})
    RunnerClient.status = AsyncMock(return_value=expected_status)
    select_user_run.side_effect = NoResultFound()

    # Act
    res = client.get("run/1/status", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert_mock_session(mock_db_session)
    assert res.status_code == HTTPStatus.NOT_FOUND
