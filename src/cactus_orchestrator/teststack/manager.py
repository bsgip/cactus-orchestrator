import asyncio
import logging
from dataclasses import dataclass

import podman as podman_api

from cactus_orchestrator.settings import PODMAN_RUNNER_URL, TEST_EXECUTION_URL_FORMAT, CactusOrchestratorError, get_current_settings

logger = logging.getLogger(__name__)

POD_READY_MAX_ATTEMPTS = 30
POD_READY_INTERVAL_SECONDS = 2


@dataclass
class TeststackResourceNames:
    runner_base_url: str
    envoy_base_url: str


def _pod_name(teststack_id: str) -> str:
    return get_current_settings().template_service_name_prefix + teststack_id


def _client() -> podman_api.PodmanClient:
    return podman_api.PodmanClient(base_url=f"unix://{get_current_settings().podman_socket}")


def get_resource_names(teststack_id: str) -> TeststackResourceNames:
    settings = get_current_settings()
    pod = _pod_name(teststack_id)
    return TeststackResourceNames(
        runner_base_url=PODMAN_RUNNER_URL.format(pod_name=pod, svc_port=settings.podman_runner_port),
        envoy_base_url=TEST_EXECUTION_URL_FORMAT.format(fqdn=settings.test_execution_fqdn, svc_name=pod),
    )


async def spawn(teststack_id: str, csip_aus_version: str, user_name: str) -> TeststackResourceNames:
    settings = get_current_settings()
    images = settings.podman_teststack_images.get(csip_aus_version)
    if not images:
        raise CactusOrchestratorError(
            f"No image config for csip_aus_version={csip_aus_version!r}. Set PODMAN_TESTSTACK_IMAGES."
        )

    pod = _pod_name(teststack_id)
    href_prefix = f"/{pod}"
    resource_names = get_resource_names(teststack_id)

    try:
        await asyncio.to_thread(_create_pod_and_containers, pod, images, href_prefix, settings)
    except Exception:
        logger.warning(f"Failed to create pod {pod}, cleaning up")
        await destroy(teststack_id)
        raise

    await _wait_for_runner_healthy(pod)

    logger.info(f"Teststack pod {pod} ready for user {user_name}")
    return resource_names


def _create_pod_and_containers(pod_name: str, images: dict[str, str], href_prefix: str, settings) -> None:
    with _client() as client:
        client.pods.create(name=pod_name, Networks={settings.podman_network: {}})

        # Postgres
        client.containers.run(
            images["postgres"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-postgres",
            environment={"POSTGRES_PASSWORD": "envoy", "POSTGRES_USER": "envoy", "POSTGRES_DB": "envoy"},
        )

        # Pubsub broker
        client.containers.run(
            images["pubsub"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-pubsub",
        )

        # Envoy — Traefik labels enable external routing
        traefik_labels = {
            "traefik.enable": "true",
            f"traefik.http.routers.{pod_name}.rule": f"PathPrefix(`{href_prefix}`)",
            f"traefik.http.routers.{pod_name}.entrypoints": "web",
            f"traefik.http.services.{pod_name}.loadbalancer.server.port": "8000",
        }
        client.containers.run(
            images["envoy"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-envoy",
            environment={
                "HREF_PREFIX": href_prefix,
                "DATABASE_URL": "postgresql+asyncpg://envoy:envoy@localhost/envoy",
                "CERT_HEADER": "ssl-client-cert",
            },
            labels=traefik_labels,
        )

        # Taskiq worker
        client.containers.run(
            images["taskiq-worker"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-taskiq-worker",
            environment={"HREF_PREFIX": href_prefix},
        )

        # Runner — internal only, no Traefik labels
        client.containers.run(
            images["runner"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-runner",
            healthcheck={
                "test": ["CMD", "curl", "-f", f"http://localhost:{settings.podman_runner_port}/health"],
                "interval": 5_000_000_000,  # nanoseconds
                "start_period": 10_000_000_000,
                "retries": 5,
            },
        )


async def _wait_for_runner_healthy(pod_name: str) -> None:
    runner_name = f"{pod_name}-runner"
    for attempt in range(POD_READY_MAX_ATTEMPTS):
        try:
            status = await asyncio.to_thread(_get_container_health, runner_name)
            if status == "healthy":
                logger.debug(f"Runner container {runner_name} healthy after {attempt + 1} attempts")
                return
            logger.debug(f"Attempt {attempt + 1}: runner health={status!r}")
        except Exception as exc:
            logger.debug(f"Attempt {attempt + 1}: error checking health: {exc}")
        await asyncio.sleep(POD_READY_INTERVAL_SECONDS)
    raise CactusOrchestratorError(f"Runner container {runner_name} did not become healthy in time.")


def _get_container_health(container_name: str) -> str:
    with _client() as client:
        container = client.containers.get(container_name)
        container.reload()
        health = container.attrs.get("State", {}).get("Health", {})
        return health.get("Status", "unknown")


async def destroy(teststack_id: str) -> None:
    pod = _pod_name(teststack_id)
    try:
        await asyncio.to_thread(_destroy_pod, pod)
        logger.info(f"Teststack pod {pod} destroyed")
    except Exception as exc:
        logger.warning(f"Error destroying pod {pod}: {exc}")


def _destroy_pod(pod_name: str) -> None:
    with _client() as client:
        try:
            pod = client.pods.get(pod_name)
            pod.stop()
            pod.remove(force=True)
        except podman_api.errors.NotFound:
            logger.info(f"Pod {pod_name} not found during destroy — already removed")
