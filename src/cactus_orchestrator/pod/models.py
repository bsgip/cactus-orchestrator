from dataclasses import dataclass

from cactus_orchestrator.model import Run, RunGroup
from cactus_orchestrator.settings import CactusOrchestratorSettings

POD_EXPOSED_PORT = 8080  # No need to configure this - it really only matters on the "internal" of a pod


@dataclass(frozen=True)
class PodImages:
    """Image references for the containers making up a single pod for a CSIP-Aus version."""

    csip_aus_version: str  # This is not an image - but a plaintext CSIPAus version that will be encoded into the env

    postgres: str
    rabbitmq: str
    init: str  # For cactus-teststack-init
    envoy: str  # This image has envoy-server, envoy-admin and envoy-notification all built in
    runner: str  # For cactus-runner


@dataclass(frozen=True)
class PodRoutes:
    """External / Internal URIs for accessing a pod's services"""

    exposed_port: int
    href_prefix: str

    internal_base_url: str  # For use from orchestrator -> runner pod.
    external_base_url: (
        str  # For use from public networks trying to access envoy (will not include any path elements for dcap/prefix)
    )
    external_host: str

    @staticmethod
    def from_run(settings: CactusOrchestratorSettings, run_group: RunGroup, run: Run) -> "PodRoutes":
        resources = PodResources.from_run(settings, run)
        if run_group.is_static_uri:
            subdomain_name = f"rg-{run.run_group_id}"
        else:
            subdomain_name = f"rg-{run.run_group_id}-r-{run.run_id}"

        external_host = f"{subdomain_name}.{settings.test_execution_fqdn}"
        return PodRoutes(
            href_prefix="/envoy/",
            exposed_port=settings.podman_runner_port,
            internal_base_url=f"http://{resources.pod_name}:{settings.podman_runner_port}",
            external_base_url=f"https://{external_host}",
            external_host=external_host,
        )


@dataclass(frozen=True)
class PodResources:
    """The podman names for various resources belonging to a test pod"""

    pod_name: str
    volume_name: str
    pod_labels: dict[str, str]

    shared_network_name: str

    container_init_name: str
    container_runner_name: str
    container_envoy_server_name: str
    container_envoy_admin_name: str
    container_envoy_notifications_name: str
    container_postgres_name: str
    container_rabbitmq_name: str

    @staticmethod
    def from_run(settings: CactusOrchestratorSettings, run: Run) -> "PodResources":
        pod_name = f"run-{run.run_id}"
        return PodResources(
            pod_name=pod_name,
            volume_name=pod_name + "-volume",
            pod_labels={
                "cactus": "true",
                "cactus:run": str(run.run_id),
                "cactus:run_group": str(run.run_group_id),
            },
            shared_network_name=settings.podman_network,
            container_init_name=pod_name + "-init",
            container_runner_name=pod_name + "-runner",
            container_envoy_server_name=pod_name + "-envoy",
            container_envoy_admin_name=pod_name + "-envoy-admin",
            container_envoy_notifications_name=pod_name + "-taskiq-worker",
            container_postgres_name=pod_name + "-postgres",
            container_rabbitmq_name=pod_name + "-rabbitmq",
        )
