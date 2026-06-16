"""Real-podman lifecycle test for the teststack manager.

This is NOT a mocked test — it spawns an actual teststack pod on the local podman host and tears it down,
verifying the full startup/shutdown path end to end. It skips itself unless a reachable podman socket,
the cactus-net network, and every required image are all present, so it stays inert in CI and in the
ordinary `uv run pytest` run (where the rootful socket isn't accessible).

To run it locally against the rootful socket:

    sudo .venv/bin/python -m pytest tests/integration/test_teststack_lifecycle.py -v
"""

import podman
import pytest
from aiohttp import ClientSession
from assertical.asserts.time import assert_nowish
from assertical.asserts.type import assert_list_type
from cactus_runner.client import RunnerClient

from cactus_orchestrator.pod.manager import create_pod_run, destroy_pod_resources, ensure_images, fetch_running_pods
from cactus_orchestrator.pod.models import PodImages, PodResources, PodRoutes, RunningPod

PODMAN_SOCKET = "/run/podman/podman.sock"
PODMAN_NETWORK = "cactus-net"
CSIP_AUS_VERSION = "1.2"


def _podman_available() -> bool:
    try:
        with podman.PodmanClient(base_url=f"unix://{PODMAN_SOCKET}") as client:
            if not client.ping() or not client.networks.exists(PODMAN_NETWORK):
                return False
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _podman_available(),
    reason=f"requires a reachable podman socket at {PODMAN_SOCKET}, the {PODMAN_NETWORK} network"
    + " (run with sudo against the rootful socket)",
)


@pytest.fixture
async def empty_pods():
    for pod in await fetch_running_pods(PODMAN_SOCKET):
        await destroy_pod_resources(PODMAN_SOCKET, pod.resources)

    yield

    for pod in await fetch_running_pods(PODMAN_SOCKET):
        await destroy_pod_resources(PODMAN_SOCKET, pod.resources)


@pytest.mark.asyncio
async def test_spawn_brings_up_healthy_pod_then_destroy_cleans_up(empty_pods):
    images = PodImages(
        csip_aus_version=CSIP_AUS_VERSION,
        postgres="docker.io/library/postgres:15",
        rabbitmq="docker.io/library/rabbitmq:3",
        init="cactusimageregistry.azurecr.io/cactus-teststack-init:158-v12",
        envoy="cactusimageregistry.azurecr.io/cactus-envoy:158-v12",
        runner="cactusimageregistry.azurecr.io/cactus-runner:158-v12",
    )

    resources = PodResources(
        pod_name="pytest-test-pod",
        volume_name="pytest-test-pod-vol",
        pod_labels={"cactus": "true", "pytest": "true", "cactus:run": "11", "cactus:run_group": "22"},
        shared_network_name=PODMAN_NETWORK,
        container_init_name="pytest-test-pod-init",
        container_runner_name="pytest-test-pod-runner",
        container_envoy_admin_name="pytest-test-pod-admin",
        container_envoy_notifications_name="pytest-test-pod-notif",
        container_envoy_server_name="pytest-test-pod-envoy",
        container_postgres_name="pytest-test-pod-pg",
        container_rabbitmq_name="pytest-test-pod-rabbitmq",
    )

    routes = PodRoutes(
        exposed_port=8080,
        href_prefix="/api",
        internal_base_url="http://pytest-test-pod:8080/",
        external_host="https://not.used/",
    )

    await ensure_images(PODMAN_SOCKET, images)

    pod_name = await create_pod_run(PODMAN_SOCKET, images, resources, routes)
    assert pod_name

    # check we can connect
    async with ClientSession(routes.internal_base_url) as session:
        health = await RunnerClient.health(session)
        assert health is True

    # check we can see it in the running pod listing
    running_pods = await fetch_running_pods(PODMAN_SOCKET)
    assert_list_type(RunningPod, running_pods, count=1)
    assert running_pods[0].name == resources.pod_name
    assert running_pods[0].run_id == 11
    assert running_pods[0].run_group_id == 22
    assert running_pods[0].is_running is True
    assert_nowish(running_pods[0].created_time)

    # destroy
    assert (await destroy_pod_resources(PODMAN_SOCKET, resources)) is True

    # destroy removes the pod and its shared volume.
    with podman.PodmanClient(base_url=f"unix://{PODMAN_SOCKET}") as client:
        assert not client.pods.exists(resources.pod_name)
        assert not client.volumes.exists(resources.volume_name)
