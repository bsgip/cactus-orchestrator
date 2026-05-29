from unittest.mock import AsyncMock, patch

import podman as podman_api
import pytest

from cactus_orchestrator.settings import _reset_current_settings
from cactus_orchestrator.teststack.manager import TeststackResourceNames, _destroy_pod, _pod_name, destroy, get_resource_names, spawn
import cactus_orchestrator.teststack.manager as teststack_manager


@pytest.fixture(autouse=True)
def podman_settings(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
    monkeypatch.setenv("TEST_EXECUTION_FQDN", "cactus.test.local")
    monkeypatch.setenv(
        "PODMAN_TESTSTACK_IMAGES",
        '{"1.0": {"postgres": "postgres:16", "pubsub": "rabbitmq:3", "teststack-init": "init:test", "envoy": "envoy:test", "taskiq-worker": "worker:test", "runner": "runner:test"}}',
    )
    _reset_current_settings()
    yield
    _reset_current_settings()


def test_get_resource_names():
    names = get_resource_names("abc123-42")
    assert names.runner_base_url == "http://envoy-svc-abc123-42:8080"
    assert names.envoy_base_url == "https://cactus.test.local/envoy-svc-abc123-42"


def test_pod_name():
    assert _pod_name("abc123-42") == "envoy-svc-abc123-42"


@pytest.mark.asyncio
async def test_destroy_handles_not_found():
    with patch.object(teststack_manager, "_destroy_pod", side_effect=podman_api.errors.NotFound("pod", None)):
        await destroy("abc123-42")  # should not raise


@pytest.mark.asyncio
async def test_spawn_cleans_up_on_failure():
    with (
        patch.object(teststack_manager, "_create_pod_and_containers", side_effect=RuntimeError("disk full")),
        patch.object(teststack_manager, "destroy", new_callable=AsyncMock) as mock_destroy,
    ):
        with pytest.raises(RuntimeError):
            await spawn("abc123-42", "1.0", "test-user")
        mock_destroy.assert_awaited_once_with("abc123-42")
