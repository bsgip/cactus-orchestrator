"""Unit tests for PodmanTeststackManager."""
from unittest.mock import AsyncMock, patch

import podman as podman_api
import pytest

from cactus_orchestrator.settings import _reset_current_settings
from cactus_orchestrator.teststack.manager import PodmanTeststackManager, TeststackResourceNames


@pytest.fixture(autouse=True)
def podman_settings(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
    monkeypatch.setenv("TEST_EXECUTION_FQDN", "cactus.test.local")
    monkeypatch.setenv(
        "PODMAN_TESTSTACK_IMAGES",
        '{"1.0": {"postgres": "postgres:16", "pubsub": "redis:7", "envoy": "envoy:test", "taskiq-worker": "worker:test", "runner": "runner:test"}}',
    )
    _reset_current_settings()
    yield
    _reset_current_settings()


def test_get_resource_names():
    manager = PodmanTeststackManager()
    names = manager.get_resource_names("abc123-42")
    assert names.runner_base_url == "http://envoy-svc-abc123-42:8080"
    assert names.envoy_base_url == "https://cactus.test.local/envoy-svc-abc123-42"


def test_pod_name():
    manager = PodmanTeststackManager()
    assert manager._pod_name("abc123-42") == "envoy-svc-abc123-42"


@pytest.mark.asyncio
async def test_destroy_handles_not_found():
    manager = PodmanTeststackManager()
    with patch.object(manager, "_destroy_pod", side_effect=podman_api.errors.NotFound("pod", None)):
        await manager.destroy("abc123-42")  # should not raise


@pytest.mark.asyncio
async def test_spawn_cleans_up_on_failure():
    manager = PodmanTeststackManager()
    with (
        patch.object(manager, "_create_pod_and_containers", side_effect=RuntimeError("disk full")),
        patch.object(manager, "destroy", new_callable=AsyncMock) as mock_destroy,
    ):
        with pytest.raises(RuntimeError):
            await manager.spawn("abc123-42", "1.0", "test-user")
        mock_destroy.assert_awaited_once_with("abc123-42")
