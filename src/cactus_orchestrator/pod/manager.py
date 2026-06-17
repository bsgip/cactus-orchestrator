import asyncio
import logging
import time
from datetime import datetime
from typing import cast

import podman
import podman.api as podman_api
import podman.errors as podman_errors

from cactus_orchestrator.pod.models import PodImages, PodResources, PodRoutes, RunningPod
from cactus_orchestrator.settings import CactusOrchestratorError

logger = logging.getLogger(__name__)

SEC = 1_000_000_000  # durations in the podman SpecGenerator are integer NANOSECONDS

POD_READY_MAX_ATTEMPTS = 30
POD_READY_INTERVAL_SECONDS = 2

# These are NOT security concerns - They are only used internally within a test pod and are not exposed externally
# We just need some constant passwords for the env
RABBIT_MQ_BROKER_URL = "amqp://guest:guest@localhost:5672"
ENVOY_DATABASE_URL_ASYNCPG = "postgresql+asyncpg://envoy:envoy@localhost/envoy"
ENVOY_DATABASE_URL_PSYCOPG = "postgresql+psycopg://envoy:envoy@localhost/envoy"
ENVOY_DATABASE_URL_PLAIN = "postgresql://envoy:envoy@localhost/envoy"


def _client(podman_socket: str) -> podman.PodmanClient:
    return podman.PodmanClient(base_url=f"unix://{podman_socket}")


async def get_podman_version(podman_socket: str) -> tuple[int, int, int]:
    """Fetches the underlying podman version detected via the podman_socket"""
    with _client(podman_socket) as client:
        try:
            raw_version = await asyncio.to_thread(_fetch_raw_podman_version, client)
        except Exception as exc:
            logger.warning(f"Failed to fetch version for {podman_socket}", exc_info=exc)
            raise

    # We are going to make a lot of assumptions here
    version_parts: list[int] = []
    for raw_v_part in raw_version.split("."):
        try:
            version_parts.append(int(raw_v_part))
        except (ValueError, TypeError):
            version_parts.append(0)
            logger.error(f"Unable to properly parse version '{raw_version}' - '{raw_v_part}' is not a number")

    if len(version_parts) < 3:
        # If we have "2.3" return (2,3,0)
        return tuple(version_parts + [0] * (3 - len(version_parts)))  # ty:ignore[invalid-return-type]
    else:
        return tuple(version_parts[:3])  # ty:ignore[invalid-return-type]


def _fetch_raw_podman_version(client: podman.PodmanClient) -> str:
    version_string: str | None = client.version().get("Version", None)
    if not version_string:
        raise Exception(
            "Couldn't extract 'Version' property from the version response. Unable to determine podman version."
        )
    return version_string


def _do_ensure_images(podman_socket: str, images: PodImages) -> int:
    pulled_images = 0
    with _client(podman_socket) as client:
        for name, image_name in images.__dict__.items():
            if name == "csip_aus_version":
                continue

            if not image_name or not isinstance(image_name, str):
                raise Exception(f"PodImages.{name} has value {image_name} ({type(image_name)}) which can't be fetched")

            try:
                client.images.get(image_name)
                logger.debug(f"PodImages.{name} '{image_name}' already exists locally.")
            except podman.errors.ImageNotFound:
                logger.info(f"PodImages.{name} '{image_name}' doesn't exist and will be fetched.")
                client.images.pull(image_name)
                pulled_images = pulled_images + 1
                logger.debug(f"PodImages.{name} '{image_name}' successfully pulled.")
    return pulled_images


async def ensure_images(podman_socket: str, images: PodImages) -> None:
    """Ensures that the specified images have been pulled for the configured podman socket. Raises an exception
    if the images cannot be pulled for whatever reason. Should return relatively quickly if all images exist."""

    t0 = time.monotonic()
    pulled_images = await asyncio.to_thread(_do_ensure_images, podman_socket, images)
    pulled_t = time.monotonic()

    if pulled_images:
        logger.info(f"{pulled_images} images were pulled in {pulled_t - t0:.1f}s")
    else:
        logger.debug("No images needed to be pulled.")


async def create_pod_run(
    podman_socket: str,
    images: PodImages,
    resources: PodResources,
    routes: PodRoutes,
) -> str:
    """Creates a new pod with the specified pod resources using the specified set of images/config options. Will wait
    until the pod is healthy before returning. Raises an exception (and attempts to clean up) on failure.

    Will not initialise runner or make any other calls into runner beyond the internal health checks.

    Returns the name of the pod."""

    t0 = time.monotonic()
    with _client(podman_socket) as client:
        try:
            pod_name = await asyncio.to_thread(_create_pod_and_containers, client, images, resources, routes)
        except Exception as exc:
            logger.warning(f"Failed to create pod {resources.pod_name}, cleaning up", exc_info=exc)
            await _do_destroy_pod_resources(client, resources)
            raise
        created = time.monotonic()

        try:
            await _wait_for_runner_healthy(client, resources)
        except Exception as exc:
            logger.warning(f"Pod {resources.pod_name} failed to turn healthy after startup, cleaning up", exc_info=exc)
            await _do_destroy_pod_resources(client, resources)
            raise
        ready = time.monotonic()

    logger.info(
        f"Pod '{pod_name}' ready (create {created - t0:.1f}s, healthy +{ready - created:.1f}s, total {ready - t0:.1f}s)"
    )

    return pod_name


def _create_pod_and_containers(
    client: podman.PodmanClient,
    images: PodImages,
    resources: PodResources,
    routes: PodRoutes,
) -> str:
    """Returns pod-name on success"""
    t0 = time.monotonic()
    timings: list[tuple[str, float]] = []

    client.volumes.create(name=resources.volume_name)
    shared_volumes = {resources.volume_name: {"bind": "/shared", "mode": "rw"}}

    # Join cactus-net (rather than mapping a host port): podman adds the pod name as a DNS alias, so
    # Traefik discovers the runner's labels and routes to the pod IP, and the orchestrator reaches the
    # runner by name.
    # userns=auto maps the pod's container-root to a high, unprivileged host UID range (allocated
    # from the rootful user's /etc/subuid + /etc/subgid). Under the rootful socket this is what keeps
    # a teststack breakout from being host-root. The pod owns the single shared namespace; every
    # member below must also pass userns_mode="auto" to join it — without it podman-py emits a
    # conflicting container-level id-mapping and the OCI runtime refuses the join.
    client.pods.create(
        name=resources.pod_name,
        Networks={resources.shared_network_name: {}},
        userns={"nsmode": "auto"},
        labels=resources.pod_labels,
    )
    timings.append(("pod", time.monotonic() - t0))

    # 1. Postgres — binds localhost so other teststacks on cactus-net can't reach it
    client.containers.run(
        images.postgres,
        detach=True,
        pod=resources.pod_name,
        userns_mode="auto",
        name=resources.container_postgres_name,
        command=["-c", "listen_addresses=localhost"],
        environment={"POSTGRES_PASSWORD": "envoy", "POSTGRES_USER": "envoy", "POSTGRES_DB": "envoy"},  # nosec # This is for internal use only - not exposed
    )
    timings.append(("postgres", time.monotonic() - t0))

    # 2. teststack-init — polls postgres itself, runs SQL migrations, exits
    client.containers.run(
        images.init,
        pod=resources.pod_name,
        userns_mode="auto",
        name=resources.container_init_name,
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
        images.rabbitmq,
        detach=True,
        pod=resources.pod_name,
        userns_mode="auto",
        name=resources.container_rabbitmq_name,
        environment={
            "RABBITMQ_DEFAULT_USER": "guest",
            "RABBITMQ_DEFAULT_PASS": "guest",  # nosec # This is for internal use only - not exposed
            "RABBITMQ_ERLANG_COOKIE": "teststack_cookie",
            "RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS": "-setcookie teststack_cookie",
        },
    )
    timings.append(("rabbitmq", time.monotonic() - t0))

    # 5. Envoy — internal only; binds 127.0.0.1 so the runner (not other teststacks) reaches it
    client.containers.run(
        images.envoy,
        detach=True,
        pod=resources.pod_name,
        userns_mode="auto",
        name=resources.container_envoy_server_name,
        environment={
            "HOST": "127.0.0.1",
            "DATABASE_URL": ENVOY_DATABASE_URL_ASYNCPG,
            "PORT": "8000",
            "HREF_PREFIX": routes.href_prefix,
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
        pod=resources.pod_name,
        userns_mode="auto",
        name=resources.container_envoy_admin_name,
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
            "ADMIN_PASSWORD": "password",  # nosec # This is for internal use only - not exposed
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
        pod=resources.pod_name,
        userns_mode="auto",
        name=resources.container_envoy_notifications_name,
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
            "HREF_PREFIX": routes.href_prefix,
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
    traefik_router_rule = f"Host(`{routes.external_host}`) && PathPrefix(`{routes.href_prefix}`)"
    traefik_labels = {
        "traefik.enable": "true",
        "traefik.docker.network": resources.shared_network_name,
        f"traefik.http.routers.{resources.pod_name}.rule": traefik_router_rule,
        f"traefik.http.routers.{resources.pod_name}.entrypoints": "web",
        f"traefik.http.services.{resources.pod_name}.loadbalancer.server.port": str(routes.exposed_port),
    }
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
            "pod": resources.pod_name,
            "userns_mode": "auto",
            "name": resources.container_runner_name,
            "labels": traefik_labels,
            "environment": {
                "PORT": str(routes.exposed_port),
                "SERVER_URL": "http://localhost:8000",
                "ENVOY_ADMIN_URL": "http://localhost:8001",
                "DATABASE_URL": ENVOY_DATABASE_URL_PSYCOPG,
                "ENVOY_ADMIN_BASICAUTH_USERNAME": "admin",
                "ENVOY_ADMIN_BASICAUTH_PASSWORD": "password",  # nosec # This is for internal use only - not exposed
                "HEADER_MEDIA_PARAM_VALUE": images.csip_aus_version,
            },
            "volumes": shared_volumes,
        }
    )

    # Regular healthcheck -> Schema2HealthConfig under "healthconfig"
    spec["healthconfig"] = {
        "Test": ["CMD-SHELL", f"curl -fiSs 'http://localhost:{routes.exposed_port}/health'"],
        "Interval": 3600 * SEC,  # every hour (we don't care too much about this once running)
        "Timeout": 5 * SEC,
        "Retries": 1,
    }

    # Startup healthcheck -> StartupHealthCheck under "startupHealthConfig"
    # (embeds the same fields as above, plus Successes)
    spec["startupHealthConfig"] = {
        "Test": ["CMD-SHELL", f"curl -fiSs 'http://localhost:{routes.exposed_port}/health'"],
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
        logger.debug(f"Pod {resources.pod_name} container create timeline: {breakdown}")

    return resources.pod_name


async def _wait_for_runner_healthy(client: podman.PodmanClient, resources: PodResources) -> None:
    for attempt in range(POD_READY_MAX_ATTEMPTS):
        try:
            status = await asyncio.to_thread(_get_container_health, client, resources.container_runner_name)
            if status.casefold() == "healthy".casefold():
                logger.debug(f"Runner container {resources.container_runner_name} healthy after {attempt + 1} attempts")
                return
            logger.debug(f"Attempt {attempt + 1}: runner health={status!r}")
        except Exception as exc:
            logger.debug(f"Attempt {attempt + 1}: error checking health: {exc}")
        await asyncio.sleep(POD_READY_INTERVAL_SECONDS)
    raise CactusOrchestratorError(f"Runner container {resources.container_runner_name} did not become healthy in time.")


def _get_container_health(client: podman.PodmanClient, container_name: str) -> str:
    container = client.containers.get(container_name)
    container.reload()
    health = container.attrs.get("State", {}).get("Health", {})
    return health.get("Status", "unknown")


async def destroy_pod_resources(podman_socket: str, resources: PodResources) -> bool:
    """Attempts to fully destroy the podman resources for a specific pod. Returns True on success, False on failure.

    (non existing resources will still report success)"""
    with _client(podman_socket) as client:
        return await _do_destroy_pod_resources(client, resources)


async def _do_destroy_pod_resources(client: podman.PodmanClient, resources: PodResources) -> bool:
    try:
        await asyncio.to_thread(_destroy_pod, client, resources)
        logger.info(f"Pod {resources.pod_name} destroyed.")
        return True
    except Exception as exc:
        logger.warning(f"Error destroying pod {resources.pod_name}", exc_info=exc)
        return False


def _destroy_pod(client: podman.PodmanClient, resources: PodResources) -> None:
    try:
        pod = client.pods.get(resources.pod_name)
        pod.remove(force=True)
        logger.debug(f"Destroyed pod '{resources.pod_name}'")
    except podman_errors.NotFound:
        logger.info(f"Pod {resources.pod_name} not found during destroy — already removed")

    # Cleanup any volumes
    try:
        client.volumes.get(resources.volume_name).remove(force=True)
        logger.debug(f"Destroyed volume '{resources.volume_name}'")
    except podman_errors.NotFound:
        pass


def _fetch_running_pods(client: podman.PodmanClient) -> list[RunningPod]:
    running_pods: list[RunningPod] = []
    for pod in client.pods.list(filters={"label": "cactus=true"}):
        created = datetime.fromisoformat(pod.attrs["Created"])
        is_running = cast(str, pod.attrs["Status"]).casefold() == "Running".casefold()

        labels: dict[str, str] = pod.attrs.get("Labels", {})
        run_id = int(labels.get("cactus:run", -1))
        run_group_id = int(labels.get("cactus:run_group", -1))
        all_networks: list[str] = pod.attrs["Networks"]
        pod_name: str = pod.attrs["Name"]
        if not all_networks:
            shared_network_name = ""
        else:
            shared_network_name = all_networks[0]

        pod_resources = PodResources.from_raw_data(shared_network_name, pod_name, run_group_id, run_id)
        running_pods.append(
            RunningPod(
                id=pod.attrs["Id"],
                name=pod_name,
                run_group_id=run_group_id,
                run_id=run_id,
                resources=pod_resources,
                created_time=created,
                is_running=is_running,
            )
        )

    return running_pods


async def fetch_running_pods(podman_socket: str) -> list[RunningPod]:
    """Enumerates all pods - returns the cactus pods with basic metadata"""
    with _client(podman_socket) as client:
        return await asyncio.to_thread(_fetch_running_pods, client)
