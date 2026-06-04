import asyncio
import dataclasses
import logging
import time
from dataclasses import dataclass

import podman
import podman.api as podman_api
import podman.errors as podman_errors

from cactus_orchestrator.settings import (
    PODMAN_RUNNER_URL,
    TEST_EXECUTION_URL_FORMAT,
    CactusOrchestratorError,
    CactusOrchestratorSettings,
    get_current_settings,
)
from cactus_orchestrator.teststack.images import TeststackImages

logger = logging.getLogger(__name__)

SEC = 1_000_000_000  # durations in the podman SpecGenerator are integer NANOSECONDS


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


def _client() -> podman.PodmanClient:
    return podman.PodmanClient(base_url=f"unix://{get_current_settings().podman_socket}")


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
    if images is None:
        raise CactusOrchestratorError(
            f"No image config for csip_aus_version={csip_aus_version!r}. Set PODMAN_TESTSTACK_IMAGES."
        )

    pod = _pod_name(teststack_id)
    href_prefix = f"/{pod}"
    resource_names = get_resource_names(teststack_id)

    t0 = time.monotonic()
    try:
        await asyncio.to_thread(_create_pod_and_containers, pod, images, href_prefix, csip_aus_version, settings)
    except Exception:
        logger.warning(f"Failed to create pod {pod}, cleaning up")
        await destroy(teststack_id)
        raise
    created = time.monotonic()

    await _wait_for_runner_healthy(pod)
    ready = time.monotonic()

    logger.info(
        f"Teststack pod {pod} ready for user {user_name} "
        f"(create {created - t0:.1f}s, healthy +{ready - created:.1f}s, total {ready - t0:.1f}s)"
    )
    return resource_names


def _ensure_images_exist(client: podman.PodmanClient, images: TeststackImages) -> None:
    """Fail fast with a clear error if any teststack image is missing on the podman host, rather than
    letting an opaque container-create error surface mid-spawn. Images are pre-pulled at deploy time."""
    refs = list(dict.fromkeys(dataclasses.astuple(images)))
    missing = [ref for ref in refs if not client.images.exists(ref)]
    if missing:
        raise CactusOrchestratorError(
            f"Teststack images missing on the podman host: {', '.join(missing)}. Pull them before spawning."
        )


def _create_pod_and_containers(
    pod_name: str,
    images: TeststackImages,
    href_prefix: str,
    csip_aus_version: str,
    settings: CactusOrchestratorSettings,
) -> None:
    shared_volume_name = f"{pod_name}-shared"
    t0 = time.monotonic()
    timings: list[tuple[str, float]] = []
    with _client() as client:
        _ensure_images_exist(client, images)

        client.volumes.create(name=shared_volume_name)
        shared_volumes = {shared_volume_name: {"bind": "/shared", "mode": "rw"}}

        # Join cactus-net (rather than mapping a host port): podman adds the pod name as a DNS alias, so
        # Traefik discovers the runner's labels and routes to the pod IP, and the orchestrator reaches the
        # runner by name.
        client.pods.create(name=pod_name, Networks={settings.podman_network: {}})
        timings.append(("pod", time.monotonic() - t0))

        # 1. Postgres — binds localhost so other teststacks on cactus-net can't reach it
        client.containers.run(
            images.postgres,
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-postgres",
            command=["-c", "listen_addresses=localhost"],
            environment={"POSTGRES_PASSWORD": "envoy", "POSTGRES_USER": "envoy", "POSTGRES_DB": "envoy"},
        )
        timings.append(("postgres", time.monotonic() - t0))

        # 2. teststack-init — polls postgres itself, runs SQL migrations, exits
        client.containers.run(
            images.teststack_init,
            pod=pod_name,
            name=f"{pod_name}-init",
            environment={
                "ENVOY_DATABASE_URL": ENVOY_DATABASE_URL_PLAIN,
                "MIGRATION_SENTINEL": "/shared/migrations.ready",
            },
            detach=True,
            remove=True,
            volumes=shared_volumes,
        )
        timings.append(("init", time.monotonic() - t0))

        # 4. RabbitMQ
        client.containers.run(
            images.pubsub,
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
        timings.append(("pubsub", time.monotonic() - t0))

        # 5. Envoy — internal only; binds 127.0.0.1 so the runner (not other teststacks) reaches it
        client.containers.run(
            images.envoy,
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-envoy",
            environment={
                "HOST": "127.0.0.1",
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
            volumes=shared_volumes,
        )
        timings.append(("envoy", time.monotonic() - t0))

        # 6. Envoy admin — same image, different entry point
        client.containers.run(
            images.envoy,
            detach=True,
            pod=pod_name,
            name=f"{pod_name}-envoy-admin",
            environment={
                "APP_MODULE": "envoy.admin.main:app",
                "HOST": "127.0.0.1",
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
        timings.append(("envoy-admin", time.monotonic() - t0))

        # 7. Taskiq worker — notification fan-out
        client.containers.run(
            images.envoy,
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
        timings.append(("taskiq-worker", time.monotonic() - t0))

        # 8. Runner — the ingress: the Traefik labels (with a StripPrefix middleware) live here, not on
        # envoy, so external device traffic flows through the runner's proxy before reaching envoy.
        runner_port = str(settings.podman_runner_port)
        traefik_labels = {
            "traefik.enable": "true",
            "traefik.docker.network": settings.podman_network,
            f"traefik.http.routers.{pod_name}.rule": f"PathPrefix(`{href_prefix}`)",
            f"traefik.http.routers.{pod_name}.entrypoints": "web",
            f"traefik.http.routers.{pod_name}.middlewares": f"{pod_name}-strip",
            f"traefik.http.middlewares.{pod_name}-strip.stripprefix.prefixes": href_prefix,
            f"traefik.http.services.{pod_name}.loadbalancer.server.port": runner_port,
        }
        # python3 (not curl) — the runner image ships python but not curl.
        runner_health_cmd = (
            f"python3 -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:{runner_port}/health\")'"
        )
        #
        # HERE BE DRAGONS - This is mostly a moment in time workaround while podman v5 isn't widely accessible
        #
        # We are using the podman api v5 - but a LOT of our servers / dev environments are podman v4
        # We have requirements for startup health checks (which podman v4 supports) but the API client does NOT
        #
        # The following abuse of the internals is how we can roll us forward
        #
        # Let podman-py build the SpecGenerator body for everything EXCEPT health checks
        # (this handles environment -> env, the volumes dict -> mounts/volumes, pod, name, etc.)
        spec = client.containers._render_payload(
            {
                "image": images.runner,
                "pod": pod_name,
                "name": f"{pod_name}-runner",
                "labels": traefik_labels,
                "environment": {
                    "PORT": runner_port,
                    "SERVER_URL": "http://localhost:8000",
                    "ENVOY_ADMIN_URL": "http://localhost:8001",
                    "DATABASE_URL": ENVOY_DATABASE_URL_PSYCOPG,
                    "ENVOY_ADMIN_BASICAUTH_USERNAME": "admin",
                    "ENVOY_ADMIN_BASICAUTH_PASSWORD": "password",
                    "HEADER_MEDIA_PARAM_VALUE": csip_aus_version,
                },
                "volumes": shared_volumes,
            }
        )

        # Regular healthcheck -> Schema2HealthConfig under "healthconfig"
        spec["healthconfig"] = {
            "Test": ["CMD-SHELL", runner_health_cmd],
            "Interval": 600 * SEC,  # every 10 minutes
            "Timeout": 5 * SEC,
            "Retries": 1,
        }

        # Startup healthcheck -> StartupHealthCheck under "startupHealthConfig"
        # (embeds the same fields as above, plus Successes)
        spec["startupHealthConfig"] = {
            "Test": ["CMD-SHELL", runner_health_cmd],
            "Interval": 1 * SEC,
            "Timeout": 5 * SEC,
            "Retries": 180,
        }

        # Submit the create request via the low-level client (mirrors CreateMixin.create)
        resp = client.api.post(
            "/containers/create",
            headers={"content-type": "application/json"},
            data=podman_api.prepare_body(spec),
        )
        resp.raise_for_status()
        container_id = resp.json()["Id"]
        container = client.containers.get(container_id)
        container.start()
        timings.append(("runner", time.monotonic() - t0))

    if logger.isEnabledFor(logging.DEBUG):
        breakdown = ", ".join(f"{name} +{offset:.2f}s" for name, offset in timings)
        logger.debug(f"Pod {pod_name} container create timeline: {breakdown}")


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
        except podman_errors.NotFound:
            logger.info(f"Pod {pod_name} not found during destroy — already removed")
        try:
            client.volumes.get(f"{pod_name}-shared").remove()
        except podman_errors.NotFound:
            pass
