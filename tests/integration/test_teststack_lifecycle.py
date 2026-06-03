"""Real-podman lifecycle test for the teststack manager.

This is NOT a mocked test — it spawns an actual teststack pod on the local podman host and tears it down,
verifying the full startup/shutdown path end to end. It skips itself unless a reachable podman socket,
the cactus-net network, and every required image are all present, so it stays inert in CI and in the
ordinary `uv run pytest` run (where the rootful socket isn't accessible).

To run it locally against the rootful socket:

    sudo .venv/bin/python -m pytest tests/integration/test_teststack_lifecycle.py -v
"""

import json
import uuid

import podman
import pytest

from cactus_orchestrator.settings import _reset_current_settings
from cactus_orchestrator.teststack.manager import _client, _pod_name, destroy, spawn

PODMAN_SOCKET = "/run/podman/podman.sock"
PODMAN_NETWORK = "cactus-net"
CSIP_AUS_VERSION = "1.2"

# Locally-present images (the 153-v12 teststack set + stock postgres/rabbitmq).
TESTSTACK_IMAGES = {
    CSIP_AUS_VERSION: {
        "postgres": "docker.io/library/postgres:15",
        "pubsub": "docker.io/library/rabbitmq:3",
        "teststack_init": "cactusimageregistry.azurecr.io/cactus-teststack-init:153-v12",
        "envoy": "cactusimageregistry.azurecr.io/cactus-envoy:153-v12",
        "runner": "cactusimageregistry.azurecr.io/cactus-runner:153-v12",
    }
}


def _podman_available() -> bool:
    try:
        with podman.PodmanClient(base_url=f"unix://{PODMAN_SOCKET}") as client:
            if not client.ping() or not client.networks.exists(PODMAN_NETWORK):
                return False
            return all(client.images.exists(ref) for images in TESTSTACK_IMAGES.values() for ref in images.values())
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _podman_available(),
    reason=f"requires a reachable podman socket at {PODMAN_SOCKET}, the {PODMAN_NETWORK} network, and the teststack "
    "images present (run with sudo against the rootful socket)",
)


@pytest.fixture
def podman_settings(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
    monkeypatch.setenv("TEST_EXECUTION_FQDN", "cactus.test.local")
    monkeypatch.setenv("PODMAN_SOCKET", PODMAN_SOCKET)
    monkeypatch.setenv("PODMAN_NETWORK", PODMAN_NETWORK)
    monkeypatch.setenv("PODMAN_TESTSTACK_IMAGES", json.dumps(TESTSTACK_IMAGES))
    _reset_current_settings()
    yield
    _reset_current_settings()


@pytest.mark.asyncio
async def test_spawn_brings_up_healthy_pod_then_destroy_cleans_up(podman_settings):
    teststack_id = f"itest{uuid.uuid4().hex[:8]}-0"
    pod = _pod_name(teststack_id)

    try:
        resource_names = await spawn(teststack_id, CSIP_AUS_VERSION, "itest-user")

        assert resource_names.runner_base_url == f"http://{pod}:8080"

        # spawn only returns once the runner's container healthcheck reports healthy — confirm the pod and
        # its members are actually up.
        with _client() as client:
            assert client.pods.exists(pod)
            runner = client.containers.get(f"{pod}-runner")
            runner.reload()
            assert runner.attrs["State"]["Health"]["Status"] == "healthy"
            for member in ("postgres", "pubsub", "envoy", "envoy-admin", "taskiq-worker", "runner"):
                assert client.containers.exists(f"{pod}-{member}"), f"missing container {pod}-{member}"
    finally:
        await destroy(teststack_id)

    # destroy removes the pod and its shared volume.
    with _client() as client:
        assert not client.pods.exists(pod)
        assert not client.volumes.exists(f"{pod}-shared")
