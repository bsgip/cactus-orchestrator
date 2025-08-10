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
