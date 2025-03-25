import base64
from datetime import datetime, timezone
from http import HTTPStatus
import os
from typing import Generator
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from fastapi_pagination import set_params, Params
from cactus_test_definitions import TestProcedureId

from cactus_orchestrator.main import app
from cactus_orchestrator.model import Run, User
from cactus_orchestrator.schema import (
    SpawnTestProcedureRequest,
    SpawnTestProcedureResponse,
    TestProcedureResponse,
)
from cactus_orchestrator.settings import HarnessOrchestratorException


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
    select_user_certificate_x509_der=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_user=AsyncMock(),
)
def test_post_spawn_test_created(client, valid_user_p12_and_der, valid_user_jwt):
    """Just a simple test, with all k8s functions stubbed, to catch anything silly in the handler"""
    # Arrange
    from cactus_orchestrator.api.run import (
        RunnerClient,
        clone_statefulset,
        select_user_certificate_x509_der,
        select_user,
        insert_run_for_user,
    )

    select_user.return_value = User(
        user_id=1, subject_id="sub", issuer_id="iss", certificate_p12_bundle=None, certificate_x509_der=None
    )
    RunnerClient.start = AsyncMock()
    clone_statefulset.return_value = "pod_name"
    select_user_certificate_x509_der.return_value = valid_user_p12_and_der[1]

    # Act
    req = SpawnTestProcedureRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    resmdl = SpawnTestProcedureResponse.model_validate(res.json())
    assert os.environ["TESTING_FQDN"] in resmdl.test_url
    insert_run_for_user.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.run",
    RunnerClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    teardown_teststack=AsyncMock(),
    select_user_certificate_x509_der=AsyncMock(),
    select_user=AsyncMock(),
    insert_run_for_user=AsyncMock(),
)
def test_post_spawn_test_teardown_on_failure(client, valid_user_jwt, valid_user_p12_and_der):
    """Asserts teardown is triggered on spawn failure"""
    # Arrange
    from cactus_orchestrator.api.run import (
        clone_statefulset,
        select_user_certificate_x509_der,
        teardown_teststack,
        select_user,
        insert_run_for_user,
    )

    select_user_certificate_x509_der.return_value = valid_user_p12_and_der[1]
    clone_statefulset.side_effect = HarnessOrchestratorException("fail")
    select_user.return_value = User(
        user_id=1, subject_id="sub", issuer_id="iss", certificate_p12_bundle=None, certificate_x509_der=None
    )

    # Act
    req = SpawnTestProcedureRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    teardown_teststack.assert_called_once()
    insert_run_for_user.assert_not_called()


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=Mock(),
    generate_client_p12=Mock(),
    insert_user=AsyncMock(),
)
def test_post_user_created(client, valid_user_jwt, ca_cert_key_pair):
    """Test successful user creation"""
    # Arrange
    from cactus_orchestrator.api.user import insert_user, generate_client_p12, fetch_certificate_key_pair

    mock_p12 = b"mock_p12_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes.return_value = b"mock_cert_data"

    generate_client_p12.return_value = (mock_p12, mock_cert)
    insert_user.return_value = AsyncMock(user_id=1)
    fetch_certificate_key_pair.return_value = ca_cert_key_pair

    # Act
    res = client.post("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    data = res.json()
    assert data["user_id"] == 1
    assert data["certificate_p12_b64"] == base64.b64encode(mock_p12).decode("utf-8")


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=Mock(),
    generate_client_p12=Mock(),
    insert_user=AsyncMock(side_effect=IntegrityError("", "", "")),
)
def test_post_user_conflict(client, valid_user_jwt, ca_cert_key_pair):
    """Test creating a user that already exists (409 Conflict)"""
    # Arrange
    from cactus_orchestrator.api.user import insert_user, generate_client_p12, fetch_certificate_key_pair

    mock_p12 = b"mock_p12_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes.return_value = b"mock_cert_data"

    generate_client_p12.return_value = (mock_p12, mock_cert)
    insert_user.return_value = AsyncMock(user_id=1)
    fetch_certificate_key_pair.return_value = ca_cert_key_pair

    # Act
    res = client.post("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CONFLICT


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=Mock(),
    generate_client_p12=Mock(),
    update_user=AsyncMock(return_value=1),
)
def test_patch_user_ok(client, valid_user_jwt, ca_cert_key_pair):
    """Test updating an existing user's certificate"""
    # Arrange
    from cactus_orchestrator.api.user import generate_client_p12, fetch_certificate_key_pair

    mock_p12 = b"mock_p12_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes.return_value = b"mock_cert_data"

    generate_client_p12.return_value = (mock_p12, mock_cert)
    fetch_certificate_key_pair.return_value = ca_cert_key_pair

    # Act
    res = client.patch("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["user_id"] == 1
    assert data["certificate_p12_b64"] == base64.b64encode(mock_p12).decode("utf-8")


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=Mock(),
    generate_client_p12=Mock(),
    update_user=AsyncMock(return_value=None),
)
def test_patch_user_notfound(client, valid_user_jwt, ca_cert_key_pair):
    """Test updating a non-existing user's certificate (404 Not Found)"""
    # Arrange
    from cactus_orchestrator.api.user import generate_client_p12, fetch_certificate_key_pair

    mock_p12 = b"mock_p12_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes.return_value = b"mock_cert_data"

    generate_client_p12.return_value = (mock_p12, mock_cert)
    fetch_certificate_key_pair.return_value = ca_cert_key_pair
    # Act
    res = client.patch("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND
    assert res.json()["detail"] == "User does not exists. Please register."


@patch(
    "cactus_orchestrator.api.user.select_user",
    AsyncMock(return_value=AsyncMock(user_id=1, certificate_p12_bundle=b"mock_p12_data")),
)
def test_get_user_ok(client, valid_user_jwt):
    """Test fetching an existing user"""
    # Act
    res = client.get("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["user_id"] == 1
    assert data["certificate_p12_b64"] == base64.b64encode(b"mock_p12_data").decode("utf-8")


@patch("cactus_orchestrator.api.user.select_user", AsyncMock(return_value=None))
def test_get_user_notfound(client, valid_user_jwt):
    """Test fetching a user that does not exist (404 Not Found)"""
    # Act
    res = client.get("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND
    assert res.json()["detail"] == "User does not exists. Please register."


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
        runfile_id=1,
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
