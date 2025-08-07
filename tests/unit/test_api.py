import os
from datetime import datetime, timezone
from http import HTTPMethod, HTTPStatus
from itertools import product
from typing import Generator
from unittest.mock import AsyncMock, Mock, call, patch

import pytest
from assertical.fake.generator import generate_class_instance
from assertical.fake.sqlalchemy import assert_mock_session, create_mock_session
from cactus_runner.models import CriteriaEntry, RequestEntry, RunnerStatus
from cactus_test_definitions import CSIPAusVersion, TestProcedureId
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi_pagination import Params, set_params
from sqlalchemy.exc import NoResultFound

from cactus_orchestrator.api.certificate import CertificateRouteType, _ca_crt_cachekey, update_ca_certificate_cache
from cactus_orchestrator.api.run import ensure_certificate_valid, finalise_run, is_all_criteria_met, teardown_teststack
from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.crud import ProcedureRunAggregated
from cactus_orchestrator.k8s.resource import generate_envoy_dcap_uri, generate_static_test_stack_id
from cactus_orchestrator.main import app
from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User
from cactus_orchestrator.schema import (
    InitRunRequest,
    InitRunResponse,
    RunResponse,
    StartRunResponse,
    TestProcedureResponse,
    TestProcedureRunSummaryResponse,
    UserConfigurationRequest,
    UserConfigurationResponse,
)
from cactus_orchestrator.settings import CactusOrchestratorException


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    yield TestClient(app)


def test_ensure_certificate_valid_when_valid(valid_user_p12_and_der):
    """Valid cert should return cert as expected"""
    _, cl_der = valid_user_p12_and_der

    result = ensure_certificate_valid("Foo", cl_der)
    assert isinstance(result, x509.Certificate)


def test_ensure_certificate_valid_expired_cert(expired_user_p12_and_der):
    """Expired cert should raise a HTTP exception"""
    _, cl_der = expired_user_p12_and_der
    with pytest.raises(HTTPException) as exc_info:
        ensure_certificate_valid("Foo", cl_der)

    assert exc_info.value.status_code == HTTPStatus.EXPECTATION_FAILED


def test_ensure_certificate_valid_no_cert():
    """Missing cert should raise a HTTP exception"""
    with pytest.raises(HTTPException) as exc_info:
        ensure_certificate_valid("Foo", None)

    assert exc_info.value.status_code == HTTPStatus.EXPECTATION_FAILED


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_run_group=AsyncMock(),
    select_active_runs_for_user=AsyncMock(),
    update_run_run_status=AsyncMock(),
)
def test_post_spawn_test_created_aggregator(client, valid_user_p12_and_der, expired_user_p12_and_der, valid_user_jwt):
    """Just a simple test of starting a aggregator cert job with all k8s functions stubbed"""
    # Arrange
    from cactus_orchestrator.api.run import (
        RunnerClient,
        clone_statefulset,
        insert_run_for_run_group,
        select_active_runs_for_user,
        select_user,
        update_run_run_status,
    )

    agg_cert_bytes = valid_user_p12_and_der[1]
    device_cert_bytes = expired_user_p12_and_der[1]
    subscription_domain = "abc.def"
    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        aggregator_certificate_x509_der=agg_cert_bytes,
        device_certificate_x509_der=device_cert_bytes,
        subscription_domain=subscription_domain,
        is_device_cert=False,
        is_static_uri=False,
    )
    RunnerClient.init = AsyncMock()
    clone_statefulset.return_value = "pod_name"
    insert_run_for_run_group.return_value = 123
    select_active_runs_for_user.return_value = []

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = client.post("run_group/123/run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    resmdl = InitRunResponse.model_validate(res.json())
    assert os.environ["TEST_EXECUTION_FQDN"] in resmdl.test_url
    assert res.headers["Location"] == "/run/123"
    insert_run_for_run_group.assert_called_once()
    update_run_run_status.assert_called_once()
    select_active_runs_for_user.assert_not_called()  # Not a static_uri test so we dont check for existing runs

    # Check init was called the correct params
    RunnerClient.init.assert_awaited_once()
    assert RunnerClient.init.call_args_list[0].kwargs["test_id"] == TestProcedureId.ALL_01
    assert RunnerClient.init.call_args_list[0].kwargs["aggregator_certificate"] == x509.load_der_x509_certificate(
        agg_cert_bytes
    ).public_bytes(serialization.Encoding.PEM).decode("utf-8")
    assert RunnerClient.init.call_args_list[0].kwargs["device_certificate"] is None
    assert RunnerClient.init.call_args_list[0].kwargs["subscription_domain"] == subscription_domain


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
def test_post_spawn_test_created_device(client, valid_user_p12_and_der, expired_user_p12_and_der, valid_user_jwt):
    """Just a simple test of starting a device cert job with all k8s functions stubbed"""
    # Arrange
    from cactus_orchestrator.api.run import (
        RunnerClient,
        clone_statefulset,
        insert_run_for_user,
        select_user,
        select_user_runs,
        update_run_run_status,
    )

    agg_cert_bytes = expired_user_p12_and_der[1]
    device_cert_bytes = valid_user_p12_and_der[1]
    subscription_domain = "abc.def"
    select_user.return_value = User(
        user_id=1,
        subject_id="sub",
        issuer_id="iss",
        aggregator_certificate_x509_der=agg_cert_bytes,
        device_certificate_x509_der=device_cert_bytes,
        subscription_domain=subscription_domain,
        is_device_cert=True,
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
    select_user_runs.assert_not_called()  # This isn't a static_uri test so we shouldn't be checking for existing runs

    # Check init was called the correct params
    RunnerClient.init.assert_awaited_once()
    assert RunnerClient.init.call_args_list[0].kwargs["test_id"] == TestProcedureId.ALL_01
    assert RunnerClient.init.call_args_list[0].kwargs["aggregator_certificate"] is None
    assert RunnerClient.init.call_args_list[0].kwargs["device_certificate"] == x509.load_der_x509_certificate(
        device_cert_bytes
    ).public_bytes(serialization.Encoding.PEM).decode("utf-8")
    assert RunnerClient.init.call_args_list[0].kwargs["subscription_domain"] == subscription_domain


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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=expired_user_p12_and_der[1],
        is_device_cert=False,
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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=valid_user_p12_and_der[1],
        is_device_cert=False,
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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=valid_user_p12_and_der[1],
        is_device_cert=False,
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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=valid_user_p12_and_der[1],
        device_certificate_p12_bundle=None,
        device_certificate_x509_der=None,
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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=valid_user_p12_and_der[1],
        device_certificate_p12_bundle=None,
        device_certificate_x509_der=None,
    )

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    teardown_teststack.assert_called_once()
    insert_run_for_user.assert_called_once()
    update_run_run_status.assert_not_called()


@pytest.mark.parametrize("cert_type", CertificateRouteType)
@patch("cactus_orchestrator.api.certificate.select_user")
def test_fetch_existing_certificate(mock_select_user, client, valid_user_jwt, cert_type: CertificateRouteType):
    # Arrange
    device_cert_data = b"device cert data"
    agg_cert_data = b"agg cert data"
    mock_select_user.return_value = User(
        aggregator_certificate_p12_bundle=agg_cert_data, device_certificate_p12_bundle=device_cert_data
    )

    # Act
    res = client.get(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.headers["content-type"] == "application/x-pkcs12"
    if cert_type == CertificateRouteType.aggregator:
        assert res.content == agg_cert_data
    else:
        assert res.content == device_cert_data


def test_fetch_existing_certificate_bad_cert_type(valid_user_jwt, client):

    # Act
    res = client.get("/certificate/agg_not_a_real_cert", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize("cert_type", CertificateRouteType)
@patch("cactus_orchestrator.api.certificate.select_user")
def test_fetch_existing_certificate_no_user(mock_select_user, client, valid_user_jwt, cert_type: CertificateRouteType):
    # Arrange
    mock_select_user.return_value = None

    # Act
    res = client.get(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize("cert_type, existing_bytes", product(CertificateRouteType, [bytes([0, 1, 99]), None]))
@patch.multiple(
    "cactus_orchestrator.api.certificate",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=Mock(),
    select_user=AsyncMock(),
    insert_user=AsyncMock(),
)
def test_create_new_certificate_existing_user(client, valid_user_jwt, ca_cert_key_pair, cert_type, existing_bytes):
    """Test creating a new certificate for a user"""
    # Arrange
    from cactus_orchestrator.api.certificate import (
        fetch_certificate_key_pair,
        generate_client_p12,
        insert_user,
        select_user,
    )

    mock_p12 = b"mock_p12_data"
    mock_der = b"mock_cert_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes = Mock(return_value=mock_der)

    mock_user = generate_class_instance(
        User,
        optional_is_none=True,
        aggregator_certificate_p12_bundle=existing_bytes,
        aggregator_certificate_x509_der=existing_bytes,
        device_certificate_p12_bundle=existing_bytes,
        device_certificate_x509_der=existing_bytes,
    )
    select_user.return_value = mock_user
    generate_client_p12.return_value = (mock_p12, mock_cert)
    fetch_certificate_key_pair.return_value = ca_cert_key_pair

    # Act
    res = client.put(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content == mock_p12
    assert res.headers["content-type"] == "application/x-pkcs12"

    if cert_type == CertificateRouteType.aggregator:
        assert mock_user.aggregator_certificate_p12_bundle == mock_p12
        assert mock_user.aggregator_certificate_x509_der == mock_der
        assert mock_user.device_certificate_p12_bundle == existing_bytes
        assert mock_user.device_certificate_x509_der == existing_bytes
    else:
        assert mock_user.aggregator_certificate_p12_bundle == existing_bytes
        assert mock_user.aggregator_certificate_x509_der == existing_bytes
        assert mock_user.device_certificate_p12_bundle == mock_p12
        assert mock_user.device_certificate_x509_der == mock_der

    select_user.assert_called()
    insert_user.assert_not_called()  # Should not be inserting a user if we find an existing one


@pytest.mark.parametrize("cert_type, existing_bytes", product(CertificateRouteType, [bytes([0, 1, 99]), None]))
@patch.multiple(
    "cactus_orchestrator.api.certificate",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=Mock(),
    select_user=AsyncMock(),
    insert_user=AsyncMock(),
)
def test_create_new_certificate_new_user(client, valid_user_jwt, ca_cert_key_pair, cert_type, existing_bytes):
    """Test creating a new certificate for a user that doesn't exist in the DB"""
    # Arrange
    from cactus_orchestrator.api.certificate import (
        fetch_certificate_key_pair,
        generate_client_p12,
        insert_user,
        select_user,
    )

    mock_p12 = b"mock_p12_data"
    mock_der = b"mock_cert_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes = Mock(return_value=mock_der)

    mock_user = generate_class_instance(
        User,
        optional_is_none=True,
        aggregator_certificate_p12_bundle=existing_bytes,
        aggregator_certificate_x509_der=existing_bytes,
        device_certificate_p12_bundle=existing_bytes,
        device_certificate_x509_der=existing_bytes,
    )
    select_user.return_value = None
    insert_user.return_value = mock_user
    generate_client_p12.return_value = (mock_p12, mock_cert)
    fetch_certificate_key_pair.return_value = ca_cert_key_pair

    # Act
    res = client.put(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content == mock_p12
    assert res.headers["content-type"] == "application/x-pkcs12"

    if cert_type == CertificateRouteType.aggregator:
        assert mock_user.aggregator_certificate_p12_bundle == mock_p12
        assert mock_user.aggregator_certificate_x509_der == mock_der
        assert mock_user.device_certificate_p12_bundle == existing_bytes
        assert mock_user.device_certificate_x509_der == existing_bytes
    else:
        assert mock_user.aggregator_certificate_p12_bundle == existing_bytes
        assert mock_user.aggregator_certificate_x509_der == existing_bytes
        assert mock_user.device_certificate_p12_bundle == mock_p12
        assert mock_user.device_certificate_x509_der == mock_der

    select_user.assert_called()
    insert_user.assert_called()


@patch.multiple(
    "cactus_orchestrator.api.certificate",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=Mock(),
    select_user=AsyncMock(),
    insert_user=AsyncMock(),
)
def test_create_new_certificate_bad_cert_type(client, valid_user_jwt):
    """Test that regenerating a cert that DNE results in a failure"""
    # Arrange
    from cactus_orchestrator.api.certificate import (
        fetch_certificate_key_pair,
        generate_client_p12,
        insert_user,
        select_user,
    )

    # Act
    res = client.put("/certificate/agg_dne_cert", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND

    fetch_certificate_key_pair.assert_not_called()
    generate_client_p12.assert_not_called()
    select_user.assert_not_called()
    insert_user.assert_not_called()


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


def test_get_version_list_populated(client, valid_user_jwt):
    """Test when there are test procedure available."""
    # Arrange
    set_params(Params(size=10, page=1))

    # Act
    res = client.get("/version", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()

    assert len(data["items"]) > 1, "Should be at least two or more entries"
    assert all([CSIPAusVersion(v["version"]).value == v["version"] for v in data["items"]]), "Version should match enum"


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
    select_user_run_group_or_raise=AsyncMock(),
    select_group_runs_aggregated_by_procedure=AsyncMock(),
)
def test_procedure_run_summaries_for_group(client, valid_user_jwt):
    """Test retrieving procedure run summaries"""
    from cactus_orchestrator.api.procedure import (
        select_group_runs_aggregated_by_procedure,
        select_user_run_group_or_raise,
    )

    # Arrange
    run_group_id = 1233
    set_params(Params(size=10, page=1))
    select_user_run_group_or_raise.return_value = User(user_id=1, subject_id="sub", issuer_id="iss")

    select_group_runs_aggregated_by_procedure.return_value = [
        ProcedureRunAggregated(TestProcedureId.LOA_08, 123, True),
        ProcedureRunAggregated(TestProcedureId.ALL_02, 0, None),
    ]

    # Act
    res = client.get(f"/procedure_runs/{run_group_id}", headers={"Authorization": f"Bearer {valid_user_jwt}"})

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

    select_user_run_group_or_raise.assert_called_once()
    select_group_runs_aggregated_by_procedure.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.procedure",
    select_user_run_group_or_raise=AsyncMock(),
    select_group_runs_for_procedure=AsyncMock(),
)
def test_get_runs_for_procedure(client, valid_user_jwt):
    """Test retrieving paginated user runs (underneath a procedure)"""
    from cactus_orchestrator.api.procedure import select_group_runs_for_procedure, select_user_run_group_or_raise

    # Arrange
    run_group_id = 1233
    set_params(Params(size=10, page=1))
    select_user_run_group_or_raise.return_value = User(user_id=1, subject_id="sub", issuer_id="iss")
    mock_run = Run(
        run_id=1,
        run_group_id=run_group_id,
        teststack_id="abc",
        testprocedure_id="ALL-01",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        finalised_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
        run_artifact_id=1,
        run_status=RunStatus.started,
        is_device_cert=False,
    )
    select_group_runs_for_procedure.return_value = [mock_run]

    # Act
    res = client.get(f"/procedure_runs/{run_group_id}/ALL-01", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, dict)
    assert "items" in data
    assert len(data["items"]) == 1
    assert data["items"][0]["run_id"] == 1
    select_user_run_group_or_raise.assert_called_once()
    select_group_runs_for_procedure.assert_called_once()


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
    select_user.return_value = User(user_id=1, subject_id="sub", issuer_id="iss", is_device_cert=False)
    mock_run = Run(
        run_id=1,
        user_id=1,
        teststack_id="abc",
        testprocedure_id="ALL-01",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        finalised_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
        run_artifact_id=1,
        run_status=RunStatus.started,
        is_device_cert=False,
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
        is_device_cert=False,
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


@pytest.mark.parametrize("is_static_uri, is_device_cert", [(True, False), (False, True)])
@patch("cactus_orchestrator.api.config.select_user_or_create")
def test_fetch_existing_config_no_certs(
    mock_select_user_or_create, client, valid_user_jwt, is_static_uri: bool, is_device_cert: bool
):
    # Arrange
    domain = "my.custom.domain"
    user = User(
        subscription_domain=domain,
        is_static_uri=is_static_uri,
        is_device_cert=is_device_cert,
        user_id=123,
        aggregator_certificate_x509_der=None,
        device_certificate_x509_der=None,
    )
    mock_select_user_or_create.return_value = user

    # Act
    res = client.get("/config", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = UserConfigurationResponse.model_validate_json(res.content)
    assert data.subscription_domain == domain
    assert data.is_static_uri is is_static_uri
    assert data.is_device_cert is is_device_cert
    if is_static_uri:
        assert data.static_uri == generate_envoy_dcap_uri(generate_static_test_stack_id(user))
    else:
        assert data.static_uri is None
    assert data.aggregator_certificate_expiry is None
    assert data.device_certificate_expiry is None


@pytest.mark.parametrize("is_static_uri, is_device_cert", [(True, False), (False, True)])
@patch("cactus_orchestrator.api.config.select_user_or_create")
def test_fetch_existing_config_domain_none_value(
    mock_select_user_or_create, client, valid_user_jwt, is_static_uri: bool, is_device_cert: bool
):
    # Arrange
    user = User(
        subscription_domain=None,
        is_static_uri=is_static_uri,
        user_id=123,
        aggregator_certificate_x509_der=None,
        device_certificate_x509_der=None,
        is_device_cert=is_device_cert,
    )
    mock_select_user_or_create.return_value = user

    # Act
    res = client.get("/config", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = UserConfigurationResponse.model_validate_json(res.content)
    assert data.subscription_domain == ""
    assert data.is_static_uri is is_static_uri
    assert data.is_device_cert is is_device_cert
    if is_static_uri:
        assert data.static_uri == generate_envoy_dcap_uri(generate_static_test_stack_id(user))
    else:
        assert data.static_uri is None
    assert data.aggregator_certificate_expiry is None
    assert data.device_certificate_expiry is None


@pytest.mark.parametrize(
    "user, input_domain, input_is_static_uri, input_is_device_cert, expected_domain, expected_is_static_uri, expected_is_device_cert",
    [
        (User(subscription_domain="", is_static_uri=False, is_device_cert=True), "", True, False, "", True, False),
        (
            User(subscription_domain="my.domain.example", is_static_uri=True, is_device_cert=True),
            "my.domain.example",
            None,
            None,
            "my.domain.example",
            True,
            True,
        ),
        (
            User(subscription_domain="my.domain.example", is_static_uri=True, is_device_cert=True),
            "my.domain.example",
            False,
            False,
            "my.domain.example",
            False,
            False,
        ),
        (
            User(subscription_domain="foo", is_static_uri=False, is_device_cert=False),
            "http://my.other.example:123/foo/bar",
            None,
            None,
            "my.other.example",
            False,
            False,
        ),
        (
            User(subscription_domain="foo", is_static_uri=True, is_device_cert=False),
            None,
            True,
            False,
            "foo",
            True,
            False,
        ),
        (
            User(subscription_domain="foo", is_static_uri=False, is_device_cert=False),
            None,
            True,
            True,
            "foo",
            True,
            True,
        ),
    ],
)
@patch("cactus_orchestrator.api.config.select_user_or_create")
def test_update_existing_config(
    mock_select_user_or_create,
    client,
    valid_user_jwt,
    user,
    input_domain: str | None,
    input_is_static_uri: bool | None,
    input_is_device_cert: bool | None,
    expected_domain: str,
    expected_is_static_uri: bool,
    expected_is_device_cert: bool,
):
    # Arrange
    mock_select_user_or_create.return_value = user

    # Act
    req = UserConfigurationRequest(
        subscription_domain=input_domain, is_static_uri=input_is_static_uri, is_device_cert=input_is_device_cert
    )
    res = client.post("/config", headers={"Authorization": f"Bearer {valid_user_jwt}"}, json=req.model_dump())

    # Assert
    assert res.status_code == HTTPStatus.CREATED

    data = UserConfigurationResponse.model_validate_json(res.content)
    assert data.subscription_domain == expected_domain
    assert data.is_static_uri == expected_is_static_uri
    assert data.is_device_cert == expected_is_device_cert
    if expected_is_static_uri:
        assert data.static_uri == generate_envoy_dcap_uri(generate_static_test_stack_id(user))
    else:
        assert data.static_uri is None
    data.device_certificate_expiry = None
    data.aggregator_certificate_expiry = None


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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=None,
        device_certificate_p12_bundle=None,
        device_certificate_x509_der=None,
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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=None,
        device_certificate_p12_bundle=None,
        device_certificate_x509_der=None,
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
        aggregator_certificate_p12_bundle=None,
        aggregator_certificate_x509_der=None,
        device_certificate_p12_bundle=None,
        device_certificate_x509_der=None,
    )
    expected_status = generate_class_instance(RunnerStatus, generate_relationships=True, step_status={})
    RunnerClient.status = AsyncMock(return_value=expected_status)
    select_user_run.side_effect = NoResultFound()

    # Act
    res = client.get("run/1/status", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert_mock_session(mock_db_session)
    assert res.status_code == HTTPStatus.NOT_FOUND
