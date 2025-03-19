import os
from typing import Generator
from unittest.mock import patch, Mock, AsyncMock
import pytest

from fastapi.testclient import TestClient

from cactus.harness_orchestrator.main import app
from cactus.harness_orchestrator.schema import (
    SpawnTestRequest,
    SpawnTestResponse,
    CsipAusTestProcedureCodes,
)
from cactus.harness_orchestrator.settings import HarnessOrchestratorException


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    yield TestClient(app)


@patch.multiple(
    "cactus.harness_orchestrator.api.user",
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
    from cactus.harness_orchestrator.api.user import (
        HarnessRunnerAsyncClient,
        clone_statefulset,
        get_user_certificate_x509_der,
    )

    HarnessRunnerAsyncClient().post_start_test = AsyncMock()
    clone_statefulset.return_value = "pod_name"
    get_user_certificate_x509_der.return_value = valid_user_p12_and_der[1]

    # Act
    req = SpawnTestRequest(code=CsipAusTestProcedureCodes.ALL01)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == 201
    resmdl = SpawnTestResponse.model_validate(res.json())
    assert os.environ["TESTING_FQDN"] in resmdl.test_url


@patch.multiple(
    "cactus.harness_orchestrator.api.user",
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
    from cactus.harness_orchestrator.api.user import (
        clone_statefulset,
        teardown_teststack,
        get_user_certificate_x509_der,
    )

    get_user_certificate_x509_der.return_value = valid_user_p12_and_der[1]
    clone_statefulset.side_effect = HarnessOrchestratorException("fail")

    # Act
    req = SpawnTestRequest(code=CsipAusTestProcedureCodes.ALL01)
    res = client.post("run", json=req.model_dump(), headers={"Authorization": f"Bearer {valid_user_jwt}"})

    # Assert
    assert res.status_code == 500
    teardown_teststack.assert_called_once()
