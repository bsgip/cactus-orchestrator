"""Resource construction via cloning of 'template' resources."""

import logging
import asyncio
from kubernetes import client
from kubernetes.client import V1StatefulSet

from cactus.harness_orchestrator.k8s_management.resource import async_k8s_api_retry
from cactus.harness_orchestrator.settings import (
    HarnessOrchestratorException,
    main_settings,
    v1_app_api,
    v1_core_api,
    v1_net_api,
    DEFAULT_INGRESS_PATH_FORMAT,
)

logger = logging.getLogger(__name__)


@async_k8s_api_retry()
async def clone_service(new_svc_name: str, new_app_label: str) -> None:
    res = v1_core_api.read_namespaced_service(
        name=main_settings.template_service_name, namespace=main_settings.testing_namespace, async_req=True
    )
    existing = await asyncio.to_thread(res.get)

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
    res = v1_core_api.create_namespaced_service(
        namespace=main_settings.testing_namespace, body=new_service, async_req=True
    )
    await asyncio.to_thread(res.get)
    logger.info(f"New service {new_svc_name} created successfully!")


@async_k8s_api_retry()
async def clone_statefulset(new_statefulset_name: str, new_service_name: str, new_app_label: str) -> None:
    res = v1_app_api.read_namespaced_stateful_set(
        name=main_settings.template_statefulset_name, namespace=main_settings.testing_namespace, async_req=True
    )
    existing = await asyncio.to_thread(res.get)

    new_spec = existing.spec
    new_spec.service_name = new_service_name
    new_spec.selector.match_labels["app"] = new_app_label
    new_spec.template.metadata.labels["app"] = new_app_label

    new_set = V1StatefulSet(
        api_version=existing.api_version,
        kind=existing.kind,
        metadata=client.V1ObjectMeta(name=new_statefulset_name),
        spec=new_spec,
    )

    res = v1_app_api.create_namespaced_stateful_set(
        body=new_set, namespace=main_settings.testing_namespace, async_req=True
    )
    await asyncio.to_thread(res.get)
    logger.info(f"New StatefulSet {new_statefulset_name} created successfully!")


@async_k8s_api_retry()
async def is_container_ready(pod_name: str, container_name: str = "envoy-db") -> bool:
    """Polls pod for specific container status. Returns True on ready."""
    res = v1_core_api.read_namespaced_pod(name=pod_name, namespace=main_settings.testing_namespace, async_req=True)
    pod = await asyncio.to_thread(res.get)
    if pod.status and pod.status.container_statuses:
        for container_status in pod.status.container_statuses:
            if container_status.name == container_name:
                return container_status.ready
    return False


@async_k8s_api_retry()
async def wait_for_pod(pod_name: str) -> None:
    # TODO: this should wait for the harness_runner container of the pod to be live
    res = await is_container_ready(pod_name)

    if res is False:
        raise HarnessOrchestratorException(f"{pod_name} failed to start.")


@async_k8s_api_retry()
async def add_ingress_rule(svc_name: str) -> None:
    """Updates the Ingress definition to include new path to to service (svc_name)."""

    res = v1_net_api.read_namespaced_ingress(
        name=main_settings.testing_ingress_name, namespace=main_settings.testing_namespace, async_req=True
    )
    ingress = await asyncio.to_thread(res.get)

    http_rule = ingress.spec.rules[0].http
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
    res = v1_net_api.patch_namespaced_ingress(
        main_settings.testing_ingress_name, main_settings.testing_namespace, ingress, async_req=True
    )
    await asyncio.to_thread(res.get)

    logger.info(f"Ingress rule added for {svc_name}.")
