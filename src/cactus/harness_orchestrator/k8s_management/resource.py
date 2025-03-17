"""Resource construction via cloning of 'template' resources."""

import logging
import asyncio
from kubernetes import client
from kubernetes.client import V1StatefulSet

from cactus.harness_orchestrator.settings import (
    main_settings,
    K8sManagerException,
    v1_app_api,
    v1_core_api,
    v1_net_api,
    DEFAULT_INGRESS_PATH_FORMAT,
)

logger = logging.getLogger(__name__)


def clone_service(new_svc_name: str, new_app_label: str):
    existing: client.V1Service = v1_core_api.read_namespaced_service(
        name=main_settings.template_service_name,
        namespace=main_settings.testing_namespace,
    )

    new_service = client.V1Service(
        api_version=existing.api_version,
        kind=existing.kind,
        metadata=client.V1ObjectMeta(name=new_svc_name),
        spec=client.V1ServiceSpec(
            selector={"app": new_app_label},
            ports=existing.spec.ports,
        ),
    )

    # Create the new service
    v1_core_api.create_namespaced_service(namespace=main_settings.testing_namespace, body=new_service)
    logger.info(f"New service {new_svc_name} created successfully!")


def clone_statefulset(new_set_name: str, new_service_name: str, new_app_label: str) -> str:
    existing = v1_app_api.read_namespaced_stateful_set(
        name=main_settings.template_statefulset_name, namespace=main_settings.testing_namespace
    )

    new_spec = existing.spec
    new_spec.service_name = new_service_name
    new_spec.selector.match_labels["app"] = new_app_label
    new_spec.template.metadata.labels["app"] = new_app_label

    new_set = V1StatefulSet(
        api_version=existing.api_version,
        kind=existing.kind,
        metadata=client.V1ObjectMeta(name=new_set_name),
        spec=new_spec,
    )

    v1_app_api.create_namespaced_stateful_set(
        body=new_set,
        namespace=main_settings.testing_namespace,
    )

    logger.info(f"New StatefulSet {new_set_name} created successfully!")
    return f"{new_set_name}-0"  # TODO: this is the k8s naming scheme of a statefulsets pod, how to better handle?


def is_container_ready(pod_name: str, container_name: str = "envoy-db") -> bool:
    """Polls pod for specific container status. Returns True on ready."""
    try:
        pod = v1_core_api.read_namespaced_pod(name=pod_name, namespace=main_settings.testing_namespace)
        if pod.status and pod.status.container_statuses:
            for container_status in pod.status.container_statuses:
                if container_status.name == container_name:
                    return container_status.ready
        return False
    except client.exceptions.ApiException as e:
        logger.debug(f"Error fetching pod status: {e}")
        return False


async def wait_for_pod(pod_name: str, max_retries: int = 10, wait_interval: int = 5) -> None:
    # TODO: this should wait for the harness_runner container of the pod to be live
    for attempt in range(max_retries):
        if await asyncio.to_thread(is_container_ready, pod_name):
            return
        await asyncio.sleep(wait_interval)

    raise K8sManagerException(f"Pod {pod_name} did not start!")


def add_ingress_rule(svc_name: str) -> None:
    """Updates the Ingress definition to include new path to to service (svc_name)."""
    try:
        ingress = v1_net_api.read_namespaced_ingress(
            name=main_settings.testing_ingress_name, namespace=main_settings.testing_namespace
        )

        http_rule = ingress.spec.rules[0].http
        if not http_rule or not http_rule.paths:
            raise K8sManagerException(f"Ingress {main_settings.testing_ingress_name} has no defined paths")

        new_rule = client.V1HTTPIngressPath(
            path=DEFAULT_INGRESS_PATH_FORMAT.format(svc_name=svc_name),
            path_type="Prefix",
            backend=client.V1IngressBackend(
                service=client.V1IngressServiceBackend(
                    name=svc_name,
                    port=client.V1ServiceBackendPort(number=main_settings.envoy_service_port),
                )
            ),
        )

        http_rule.paths.append(new_rule)
        v1_net_api.patch_namespaced_ingress(
            main_settings.testing_ingress_name, main_settings.testing_namespace, ingress
        )

        logger.info(f"Ingress rule added for {svc_name}.")

    except client.exceptions.ApiException as e:
        logger.error(f"Failed to update Ingress: {e}")
        raise K8sManagerException("Failed to update Ingress")
