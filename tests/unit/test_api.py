import base64
from http import HTTPStatus
import os
from typing import Generator
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from cactus_orchestrator.main import app
from cactus_orchestrator.schema import CsipAusTestProcedureCodes, SpawnTestRequest, SpawnTestResponse
from cactus_orchestrator.settings import HarnessOrchestratorException


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    yield TestClient(app)


@patch.multiple(
    "cactus_orchestrator.api.user",
    HarnessRunnerAsyncClient=Mock(),
    clone_statefulset=AsyncMock(),
    fetch_certificate_key_pair=Mock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    get_user_certificate_x509_der=AsyncMock(),
)
def test_post_spawn_test_basic(client, valid_user_p12_and_der, valid_user_jwt):
    """Just a simple test, with all k8s functions stubbed, to catch anything silly in the handler"""
    # Arrange
    from cactus_orchestrator.api.user import (
        HarnessRunnerAsyncClient,
        clone_statefulset,
        select_user_certificate_x509_der,
    )

    HarnessRunnerAsyncClient().post_start_test = AsyncMock()
    clone_statefulset.return_value = "pod_name"
    select_user_certificate_x509_der.return_value = valid_user_p12_and_der[1]

    # Act
    req = SpawnTestRequest(code=CsipAusTestProcedureCodes.ALL01)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    resmdl = SpawnTestResponse.model_validate(res.json())
    assert os.environ["TESTING_FQDN"] in resmdl.test_url


@patch.multiple(
    "cactus_orchestrator.api.user",
    HarnessRunnerAsyncClient=Mock(),
    clone_statefulset=AsyncMock(),
    fetch_certificate_key_pair=Mock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    teardown_teststack=AsyncMock(),
    get_user_certificate_x509_der=AsyncMock(),
)
def test_post_spawn_test_fails(client, valid_user_jwt, valid_user_p12_and_der):
    """Basic test to check teardown on failure"""
    # Arrange
    from cactus_orchestrator.api.user import clone_statefulset, select_user_certificate_x509_der, teardown_teststack

    select_user_certificate_x509_der.return_value = valid_user_p12_and_der[1]
    clone_statefulset.side_effect = HarnessOrchestratorException("fail")

    # Act
    req = SpawnTestRequest(code=CsipAusTestProcedureCodes.ALL01)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    teardown_teststack.assert_called_once()


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=AsyncMock(),
    insert_user=AsyncMock(),
)
def test_create_new_user(client, valid_user_jwt):
    """Test successful user creation"""
    # Arrange
    from cactus_orchestrator.api.user import insert_user, generate_client_p12

    mock_p12 = b"mock_p12_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes.return_value = b"mock_cert_data"

    generate_client_p12.return_value = (mock_p12, mock_cert)
    insert_user.return_value = AsyncMock(user_id=1)

    # Act
    res = client.post("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    data = res.json()
    assert data["user_id"] == 1
    assert data["certificate_p12_b64"] == base64.b64encode(mock_p12).decode("utf-8")


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=AsyncMock(),
    insert_user=AsyncMock(side_effect=HarnessOrchestratorException("User already exists.")),
)
def test_create_new_user_conflict(client, valid_user_jwt):
    """Test creating a user that already exists (409 Conflict)"""
    # Act
    res = client.post("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CONFLICT
    assert res.json()["detail"] == "User already exists."


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=AsyncMock(),
    upsert_user=AsyncMock(return_value=1),
)
def test_update_existing_user_certificate(client, valid_user_jwt):
    """Test updating an existing user's certificate"""
    # Arrange
    from cactus_orchestrator.api.user import generate_client_p12

    mock_p12 = b"mock_p12_data"
    mock_cert = AsyncMock()
    mock_cert.public_bytes.return_value = b"mock_cert_data"

    generate_client_p12.return_value = (mock_p12, mock_cert)

    # Act
    res = client.patch("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    data = res.json()
    assert data["user_id"] == 1
    assert data["certificate_p12_b64"] == base64.b64encode(mock_p12).decode("utf-8")


@patch.multiple(
    "cactus_orchestrator.api.user",
    fetch_certificate_key_pair=AsyncMock(),
    generate_client_p12=AsyncMock(),
    upsert_user=AsyncMock(return_value=None),
)
def test_update_nonexistent_user_certificate(client, valid_user_jwt):
    """Test updating a non-existing user's certificate (404 Not Found)"""
    # Act
    res = client.patch("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND
    assert res.json()["detail"] == "User does not exists. Please register."


@patch(
    "cactus_orchestrator.api.user.select_user",
    AsyncMock(return_value=AsyncMock(user_id=1, certificate_p12_bundle=b"mock_p12_data")),
)
def test_get_existing_user(client, valid_user_jwt):
    """Test fetching an existing user"""
    # Act
    res = client.get("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["user_id"] == 1
    assert data["certificate_p12_b64"] == base64.b64encode(b"mock_p12_data").decode("utf-8")


@patch("cactus_orchestrator.api.user.select_user", AsyncMock(return_value=None))
def test_get_nonexistent_user(client, valid_user_jwt):
    """Test fetching a user that does not exist (404 Not Found)"""
    # Act
    res = client.get("/user", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND
    assert res.json()["detail"] == "User does not exists. Please register."
