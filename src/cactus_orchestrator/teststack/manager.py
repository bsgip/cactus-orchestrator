import asyncio
import logging
from dataclasses import dataclass

import podman as podman_api

from cactus_orchestrator.settings import (
    PODMAN_RUNNER_URL,
    TEST_EXECUTION_URL_FORMAT,
    CactusOrchestratorError,
    CactusOrchestratorSettings,
    get_current_settings,
)

logger = logging.getLogger(__name__)

POD_READY_MAX_ATTEMPTS = 30
POD_READY_INTERVAL_SECONDS = 2

RABBIT_MQ_BROKER_URL = "amqp://guest:guest@localhost:5672"
ENVOY_DATABASE_URL_ASYNCPG = "postgresql+asyncpg://envoy:envoy@localhost/envoy"
ENVOY_DATABASE_URL_PSYCOPG = "postgresql+psycopg://envoy:envoy@localhost/envoy"
ENVOY_DATABASE_URL_PLAIN = "postgresql://envoy:envoy@localhost/envoy"


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
        await asyncio.to_thread(_create_pod_and_containers, pod, images, href_prefix, csip_aus_version, settings)
    except Exception:
        logger.warning(f"Failed to create pod {pod}, cleaning up")
        await destroy(teststack_id)
        raise

    await _wait_for_runner_healthy(pod)

    logger.info(f"Teststack pod {pod} ready for user {user_name}")
    return resource_names


def _create_pod_and_containers(
    pod_name: str, images: dict[str, str], href_prefix: str, csip_aus_version: str, settings: CactusOrchestratorSettings
) -> None:
    shared_volume_name = f"{pod_name}-shared"
    with _client() as client:
        client.volumes.create(name=shared_volume_name)
        shared_volumes = {shared_volume_name: {"bind": "/shared", "mode": "rw"}}

        client.pods.create(
            name=pod_name,
            portmappings=[
                {
                    "container_port": settings.podman_runner_port,
                    "host_port": 0,  # Let the OS find a free port
                    "protocol": "tcp",
                }
            ],
        )

        # 1. Postgres
        client.containers.run(
            images["postgres"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-postgres",
            environment={"POSTGRES_PASSWORD": "envoy", "POSTGRES_USER": "envoy", "POSTGRES_DB": "envoy"},
        )

        # 2. teststack-init — polls postgres itself, runs SQL migrations, exits
        client.containers.run(
            images["teststack-init"],
            pod=pod_name,
            name=f"{pod_name}-init",
            environment={
                "ENVOY_DATABASE_URL": ENVOY_DATABASE_URL_PLAIN,
                "MIGRATION_SENTINEL": "/shared/migrations.ready",
            },
            detach=True,
            # remove=True,
            volumes=shared_volumes,
        )

        # 4. RabbitMQ
        client.containers.run(
            images["pubsub"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-pubsub",
            environment={
                "RABBITMQ_DEFAULT_USER": "guest",
                "RABBITMQ_DEFAULT_PASS": "guest",
                "RABBITMQ_ERLANG_COOKIE": "teststack_cookie",
                "RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS": "-setcookie teststack_cookie",
            },
        )

        # 5. Envoy — Traefik labels enable external routing
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
                "DATABASE_URL": ENVOY_DATABASE_URL_ASYNCPG,
                "PORT": "8000",
                "HREF_PREFIX": href_prefix,
                "CERT_HEADER": "ssl-client-cert",
                "ENABLE_NOTIFICATIONS": "True",
                "RABBIT_MQ_BROKER_URL": RABBIT_MQ_BROKER_URL,
                "ALLOW_DEVICE_REGISTRATION": "True",
                "STATIC_REGISTRATION_PIN": "11111",
                "LOG_CONFIG": "logconf.server.json",
                "NOTIFICATION_DISABLE_TLS_VERIFY": "True",
                "MIGRATION_SENTINEL": "/shared/migrations.ready",
            },
            labels=traefik_labels,
            volumes=shared_volumes,
        )

        # 6. Envoy admin — same image, different entry point
        client.containers.run(
            images["envoy"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-envoy-admin",
            environment={
                "APP_MODULE": "envoy.admin.main:app",
                "PORT": "8001",
                "DATABASE_URL": ENVOY_DATABASE_URL_ASYNCPG,
                "CERT_HEADER": "ssl-client-cert",
                "ENABLE_NOTIFICATIONS": "True",
                "RABBIT_MQ_BROKER_URL": RABBIT_MQ_BROKER_URL,
                "ALLOW_DEVICE_REGISTRATION": "True",
                "ADMIN_USERNAME": "admin",
                "ADMIN_PASSWORD": "password",
                "LOG_CONFIG": "logconf.admin.json",
                "MIGRATION_SENTINEL": "/shared/migrations.ready",
            },
            volumes=shared_volumes,
        )

        # 7. Taskiq worker — notification fan-out
        client.containers.run(
            images["envoy"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-taskiq-worker",
            command=[
                "taskiq",
                "worker",
                "--no-configure-logging",
                "envoy.notification.main:broker",
                "envoy.notification.task.check",
                "envoy.notification.task.transmit",
            ],
            environment={
                "DATABASE_URL": ENVOY_DATABASE_URL_ASYNCPG,
                "HREF_PREFIX": href_prefix,
                "CERT_HEADER": "ssl-client-cert",
                "ENABLE_NOTIFICATIONS": "True",
                "RABBIT_MQ_BROKER_URL": RABBIT_MQ_BROKER_URL,
                "ALLOW_DEVICE_REGISTRATION": "True",
                "LOG_CONFIG": "logconf.notification.json",
                "MIGRATION_SENTINEL": "/shared/migrations.ready",
            },
            volumes=shared_volumes,
        )

        # 8. Runner — internal only, no Traefik labels
        client.containers.run(
            images["runner"],
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-runner",
            environment={
                "PORT": str(settings.podman_runner_port),
                "SERVER_URL": "http://localhost:8000",
                "ENVOY_ADMIN_URL": "http://localhost:8001",
                "DATABASE_URL": ENVOY_DATABASE_URL_PSYCOPG,
                "ENVOY_ADMIN_BASICAUTH_USERNAME": "admin",
                "ENVOY_ADMIN_BASICAUTH_PASSWORD": "password",
                "HEADER_MEDIA_PARAM_VALUE": csip_aus_version,
            },
            volumes=shared_volumes,
            # These health checks run during normal operation
            health_cmd=f"CMD-SHELL curl -f 'http://localhost:{settings.podman_runner_port}/health'",
            health_interval="60s",
            health_timeout="5s",
            health_retries="1",
            # These health checks occur at startup
            health_startup_cmd=f"CMD-SHELL curl -f 'http://localhost:{settings.podman_runner_port}/health'",
            health_startup_interval="1s",
            health_startup_timeout="5s",
            health_startup_retries="180",
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
        try:
            client.volumes.get(f"{pod_name}-shared").remove()
        except podman_api.errors.NotFound:
            pass
