import os
from typing import Generator
from unittest.mock import patch, Mock, AsyncMock
import pytest

from fastapi.testclient import TestClient

from cactus.harness_orchestrator.main import app
from cactus.harness_orchestrator.schema import SpawnTestRequest, SpawnTestResponse, CsipAusTestProcedureCodes


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    yield TestClient(app)


@patch.multiple(
    "cactus.harness_orchestrator.main",
    HarnessRunnerAsyncClient=Mock(),
    clone_statefulset=Mock(),
    fetch_certificate_key_pair=Mock(),
    wait_for_pod=AsyncMock(),
    add_ingress_rule=Mock(),
    clone_service=Mock(),
)
def test_post_spawn_test_basic(client, ca_cert_key_pair):
    """Just a simple test, with all k8s functions stubbed, to catch anything silly in the handler"""
    # Arrange
    from cactus.harness_orchestrator.main import HarnessRunnerAsyncClient, clone_statefulset, fetch_certificate_key_pair

    HarnessRunnerAsyncClient().post_start_test = AsyncMock(return_value=True)
    clone_statefulset.return_value = "pod_name"
    fetch_certificate_key_pair.return_value = ca_cert_key_pair

    # Act
    req = SpawnTestRequest(code=CsipAusTestProcedureCodes.ALL01)
    res = client.post("spawn-test", json=req.model_dump())

    # Assert
    assert res.status_code == 201
    resmdl = SpawnTestResponse.model_validate(res.json())
    assert "BEGIN CERTIFICATE" in resmdl.ca_cert
    assert os.environ["TESTING_FQDN"] in resmdl.test_url
