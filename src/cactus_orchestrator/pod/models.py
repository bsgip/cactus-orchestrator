from dataclasses import dataclass
from datetime import datetime

from cactus_orchestrator.model import Run, RunGroup


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
    def from_run(
        test_execution_fqdn: str, exposed_port: int, resources: "PodResources", run_group: RunGroup, run: Run
    ) -> "PodRoutes":
        if run_group.is_static_uri:
            subdomain_name = f"rg-{run.run_group_id}"
        else:
            subdomain_name = f"rg-{run.run_group_id}-r-{run.run_id}"

        external_host = f"{subdomain_name}.{test_execution_fqdn}"
        return PodRoutes(
            href_prefix="/envoy",
            exposed_port=exposed_port,
            internal_base_url=f"http://{resources.pod_name}:{exposed_port}",
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
    def from_run(shared_network_name: str, run: Run) -> "PodResources":
        return PodResources.from_raw_data(shared_network_name, run.run_group_id, run.run_id)

    @staticmethod
    def from_raw_data(shared_network_name: str, run_group_id: int, run_id: int) -> "PodResources":
        pod_name = f"run-{run_id}"
        return PodResources(
            pod_name=pod_name,
            volume_name=pod_name + "-volume",
            pod_labels={
                "cactus": "true",
                "cactus:run": str(run_id),
                "cactus:run_group": str(run_group_id),
            },
            shared_network_name=shared_network_name,
            container_init_name=pod_name + "-init",
            container_runner_name=pod_name + "-runner",
            container_envoy_server_name=pod_name + "-envoy",
            container_envoy_admin_name=pod_name + "-envoy-admin",
            container_envoy_notifications_name=pod_name + "-taskiq-worker",
            container_postgres_name=pod_name + "-postgres",
            container_rabbitmq_name=pod_name + "-rabbitmq",
        )


@dataclass(frozen=True)
class RunningPod:
    """Metadata about a cactus pod that is still registered in podman"""

    id: str
    name: str  # Name of the pod - as reported by podman (should be the same as resources.pod_name unless changes)
    run_group_id: int  # Which run/group created this pod
    run_id: int  # Which run/group created this pod
    created_time: datetime  # tz aware
    is_running: bool
    resources: PodResources
