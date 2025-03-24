import base64
from http import HTTPStatus
import os
from typing import Generator
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from fastapi_pagination import set_params, Params

from cactus_orchestrator.main import app
from cactus_orchestrator.schema import CsipAusTestProcedureCodes, SpawnTestRequest, SpawnTestResponse, TestProcedureResponse
from cactus_orchestrator.settings import HarnessOrchestratorException


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    yield TestClient(app)


@patch.multiple(
    "cactus_orchestrator.api.run",
    HarnessRunnerAsyncClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    select_user_certificate_x509_der=AsyncMock(),
)
def test_post_spawn_test_created(client, valid_user_p12_and_der, valid_user_jwt):
    """Just a simple test, with all k8s functions stubbed, to catch anything silly in the handler"""
    # Arrange
    from cactus_orchestrator.api.run import (
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
    "cactus_orchestrator.api.run",
    HarnessRunnerAsyncClient=Mock(),
    clone_statefulset=AsyncMock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=AsyncMock(),
    clone_service=AsyncMock(),
    teardown_teststack=AsyncMock(),
    select_user_certificate_x509_der=AsyncMock(),
)
def test_post_spawn_test_teardown_on_failure(client, valid_user_jwt, valid_user_p12_and_der):
    """Asserts teardown is triggered on spawn failure"""
    # Arrange
    from cactus_orchestrator.api.run import clone_statefulset, select_user_certificate_x509_der, teardown_teststack

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
    insert_user=AsyncMock(side_effect=IntegrityError("","","")),
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


@patch("cactus_orchestrator.api.procedure.test_procedure_responses", [
    TestProcedureResponse(
        code="abc",
        category="a",
        description="blah",

    ),
    TestProcedureResponse(
        code="bcd",
        category="b",
        description="blah",
    )
])
def test_get_test_procedure_list_populated(client, valid_user_jwt):
    """Test when there are test procedure available."""
    # Arrange
    set_params(Params(size=10, page=1))

    # Act
    res = client.get("/procedure", headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2
    assert data["items"][0]["code"] == "abc"
    assert data["items"][1]["code"] == "bcd"