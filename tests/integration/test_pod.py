"""Real-podman lifecycle test for the teststack manager.

This is NOT a mocked test — it spawns an actual teststack pod on the local podman host and tears it down,
verifying the full startup/shutdown path end to end. It skips itself unless a reachable podman socket,
the cactus-net network, and every required image are all present, so it stays inert in CI and in the
ordinary `uv run pytest` run (where the rootful socket isn't accessible).

To run it locally against the rootful socket:

    sudo .venv/bin/python -m pytest tests/integration/test_teststack_lifecycle.py -v
"""

import cactus_schema.runner.uri as runner_uri
import podman
import pytest
from assertical.asserts.time import assert_nowish
from assertical.asserts.type import assert_list_type
from podman.errors import ImageNotFound

from cactus_orchestrator.pod.manager import create_pod_run, destroy_pod_resources, ensure_images, fetch_running_pods
from cactus_orchestrator.pod.models import PodImages, PodResources, PodRoutes, RunningPod

PODMAN_SOCKET = "/run/podman/podman.sock"
PODMAN_NETWORK = "pytest-cactus"
CSIP_AUS_VERSION = "1.2"
CURL_IMAGE = "docker.io/curlimages/curl"  # Simple image that has curl installed


def _podman_available() -> bool:
    try:
        with podman.PodmanClient(base_url=f"unix://{PODMAN_SOCKET}") as client:
            if not client.ping():
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
def ensure_network():
    with podman.PodmanClient(base_url=f"unix://{PODMAN_SOCKET}") as client:
        if not client.networks.exists(PODMAN_NETWORK):
            client.networks.create(PODMAN_NETWORK, dns_enabled=True)


@pytest.fixture
async def empty_pods():
    """Cleans up the pytest pods both BEFORE and AFTER running the test"""
    for pod in await fetch_running_pods(PODMAN_SOCKET):
        await destroy_pod_resources(PODMAN_SOCKET, pod.resources)

    yield

    for pod in await fetch_running_pods(PODMAN_SOCKET):
        await destroy_pod_resources(PODMAN_SOCKET, pod.resources)


@pytest.fixture
def in_network_curl():
    with podman.PodmanClient(base_url=f"unix://{PODMAN_SOCKET}") as client:
        try:
            client.images.get(CURL_IMAGE)
        except ImageNotFound:
            client.images.pull(CURL_IMAGE)

        def do_curl(uri: str) -> tuple[int, str]:
            container = client.containers.create(
                image=CURL_IMAGE,
                command=["curl", "-fiSs", uri],
                networks={PODMAN_NETWORK: {}},
            )
            try:
                container.start()
                exit_code = container.wait(timeout=10)
                stdout_bytes = container.logs(stdout=True, stderr=True)
                container.remove()
                if isinstance(stdout_bytes, bytes):
                    return (exit_code, stdout_bytes.decode())
                else:
                    return (exit_code, b"".join(stdout_bytes).decode())
            except Exception as exc:
                container.remove()
                return (-1, str(exc))

        yield do_curl


@pytest.mark.asyncio
async def test_spawn_brings_up_healthy_pod_then_destroy_cleans_up(ensure_network, empty_pods, in_network_curl):
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

    with podman.PodmanClient(base_url=f"unix://{PODMAN_SOCKET}") as client:
        if client.volumes.exists(resources.volume_name):
            client.volumes.remove(resources.volume_name, force=True)

    await ensure_images(PODMAN_SOCKET, images)

    pod_name = await create_pod_run(PODMAN_SOCKET, images, resources, routes)
    assert pod_name

    # check we can connect - we have to do this from WITHIN the podman-network (as if this test was operating
    # alongside the test pod)
    health_uri = routes.internal_base_url + runner_uri.Health.strip("/")
    status_code, stdout_text = in_network_curl(health_uri)
    assert status_code == 0, f"ExitCode {status_code} from {health_uri}\n{stdout_text}"

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
