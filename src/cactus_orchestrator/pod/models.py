from dataclasses import dataclass
from datetime import datetime

from cactus_orchestrator.model import Run, RunGroup


def generate_static_uri_external_host(cactus_fqdn: str, run_group_id: int) -> str:
    return f"rg-{run_group_id}.{cactus_fqdn}"


def generate_dynamic_uri_external_host(cactus_fqdn: str, run_group_id: int, run_id: int) -> str:
    return f"rg-{run_group_id}-r-{run_id}.{cactus_fqdn}"


@dataclass(frozen=True)
class PodImages:
    """Image references for the containers making up a single pod for a CSIP-Aus version."""

    csip_aus_version: str  # This is not an image - but a plaintext CSIPAus version that will be encoded into the env

    db: str  # For cactus-db - it's postgres with the latest envoy migrations applied
    envoy: str  # This image has envoy-server, envoy-admin and envoy-notification all built in
    runner: str  # For cactus-runner


@dataclass(frozen=True)
class PodRoutes:
    """External / Internal URIs for accessing a pod's services"""

    exposed_port: int
    href_prefix: str

    internal_base_url: str  # For use from orchestrator -> runner pod.
    external_host: str

    @staticmethod
    def from_run(
        cactus_fqdn: str, envoy_href: str, exposed_port: int, resources: "PodResources", run_group: RunGroup, run: Run
    ) -> "PodRoutes":
        if run_group.is_static_uri:
            external_host = generate_static_uri_external_host(cactus_fqdn, run.run_group_id)
        else:
            external_host = generate_dynamic_uri_external_host(cactus_fqdn, run.run_group_id, run.run_id)

        return PodRoutes(
            href_prefix=envoy_href,
            exposed_port=exposed_port,
            internal_base_url=f"http://{resources.pod_name}:{exposed_port}",
            external_host=external_host,
        )


@dataclass(frozen=True)
class PodResources:
    """The podman names for various resources belonging to a test pod"""

    pod_name: str  # The name to be used when creating a new pod
    volume_name: str
    pod_labels: dict[str, str]

    shared_network_name: str

    container_init_name: str
    container_runner_name: str
    container_envoy_server_name: str
    container_envoy_admin_name: str
    container_postgres_name: str

    @staticmethod
    def from_run(shared_network_name: str, run: Run) -> "PodResources":
        return PodResources.from_raw_data(shared_network_name, run.pod_name, run.run_id, run.run_group_id)

    @staticmethod
    def from_raw_data(shared_network_name: str, pod_name: str | None, run_id: int, run_group_id: int) -> "PodResources":
        pod_name = pod_name if pod_name is not None else f"run-{run_id}"
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
            container_postgres_name=pod_name + "-postgres",
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


@dataclass(frozen=True)
class PodPKI:
    """mTLS/PKI details that are injected into a running pod"""

    # The utility server (envoy) keys used for establishing outgoing mTLS connections for subscription/notifications
    server_ca_bytes: bytes
    server_cert_bytes: bytes
    server_key_bytes: bytes

    @staticmethod
    def from_paths(serca_path: str, envoy_ee_fullchain_path: str, envoy_ee_key_path: str) -> "PodPKI":
        with open(serca_path, "rb") as f:
            server_ca_bytes = f.read()
        with open(envoy_ee_fullchain_path, "rb") as f:
            server_cert_bytes = f.read()
        with open(envoy_ee_key_path, "rb") as f:
            server_key_bytes = f.read()
        return PodPKI(
            server_ca_bytes=server_ca_bytes,
            server_cert_bytes=server_cert_bytes,
            server_key_bytes=server_key_bytes,
        )
