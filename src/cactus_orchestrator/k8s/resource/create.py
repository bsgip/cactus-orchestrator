"""Resource construction via cloning of 'template' resources."""

import asyncio
import logging
from multiprocessing.pool import ApplyResult

from kubernetes import client
from kubernetes.client import V1EnvVar, V1StatefulSet

from cactus_orchestrator.k8s.resource import async_k8s_api_retry
from cactus_orchestrator.settings import (
    DEFAULT_INGRESS_PATH_FORMAT,
    CactusOrchestratorException,
    get_current_settings,
    v1_app_api,
    v1_core_api,
    v1_net_api,
)

logger = logging.getLogger(__name__)


@async_k8s_api_retry()
async def clone_service(new_svc_name: str, new_app_label: str) -> None:
    res: ApplyResult = v1_core_api.read_namespaced_service(
        name=get_current_settings().template_service_name,
        namespace=get_current_settings().teststack_templates_namespace,
        async_req=True,
    )  # type: ignore
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
        namespace=get_current_settings().test_execution_namespace, body=new_service, async_req=True
    )  # type: ignore
    await asyncio.to_thread(res.get)
    logger.info(f"New service {new_svc_name} created successfully!")


@async_k8s_api_retry()
async def clone_statefulset(new_statefulset_name: str, new_service_name: str, new_app_label: str) -> None:
    template_set_name = get_current_settings().template_statefulset_name
    template_namespace = get_current_settings().teststack_templates_namespace
    res: ApplyResult = v1_app_api.read_namespaced_stateful_set(
        name=template_set_name,
        namespace=template_namespace,
        async_req=True,
    )  # type: ignore
    existing: V1StatefulSet = await asyncio.to_thread(res.get)

    # Rework the discovered spec into a new spec that's specific to the new service/labels
    new_spec = existing.spec
    if new_spec is None:
        raise CactusOrchestratorException(f"{template_namespace} {template_set_name} - missing top level spec")
    new_spec.service_name = new_service_name
    if new_spec.selector.match_labels is None:
        new_spec.selector.match_labels = {"app": new_app_label}
    else:
        new_spec.selector.match_labels["app"] = new_app_label
    if new_spec.template.metadata is None:
        raise CactusOrchestratorException(f"{template_namespace} {template_set_name} - missing spec.template.metadata")
    if new_spec.template.metadata.labels is None:
        new_spec.template.metadata.labels = {"app": new_app_label}
    else:
        new_spec.template.metadata.labels["app"] = new_app_label

    # We will need to also inject the HREF_PREFIX env variable for the "envoy" container to ensure that all generated
    # hrefs properly include the prefix such that /edev will be encoded as /envoy-svc-abc123/edev
    href_env = V1EnvVar(name="HREF_PREFIX", value=f"/{new_service_name}", value_from=None)
    if new_spec.template.spec is None:
        raise CactusOrchestratorException(f"{template_namespace} {template_set_name} - missing template spec")
    envoy_containers = [c for c in new_spec.template.spec.containers if c.name == "envoy"]
    if len(envoy_containers) != 1:
        raise CactusOrchestratorException(
            f"{template_namespace} {template_set_name} - Expected 1 but found {len(envoy_containers)} envoy containers."
        )
    container_to_update = envoy_containers[0]
    if container_to_update.env is None:
        container_to_update.env = [href_env]
    else:
        container_to_update.env.append(href_env)

    new_set = V1StatefulSet(
        api_version=existing.api_version,
        kind=existing.kind,
        metadata=client.V1ObjectMeta(name=new_statefulset_name),
        spec=new_spec,
    )

    res = v1_app_api.create_namespaced_stateful_set(
        body=new_set, namespace=get_current_settings().test_execution_namespace, async_req=True
    )  # type: ignore
    await asyncio.to_thread(res.get)
    logger.info(f"New StatefulSet {new_statefulset_name} created successfully!")


@async_k8s_api_retry()
async def is_container_ready(pod_name: str, container_name: str | None = None, namespace: str | None = None) -> bool:
    """Checks pod for specific container status. Returns True on ready."""
    settings = get_current_settings()
    container_name = container_name or settings.pod_readiness_check_container_name
    namespace = namespace or settings.test_execution_namespace
    res: ApplyResult = v1_core_api.read_namespaced_pod(
        name=pod_name, namespace=namespace, async_req=True
    )  # type: ignore
    pod = await asyncio.to_thread(res.get)

    if not pod or not pod.status:
        return False

    statuses = (pod.status.container_statuses or []) + (pod.status.init_container_statuses or [])
    for status in statuses:
        if status.name == container_name:
            return status.ready

    return False


async def is_pod_ready(pod_name: str, namespace: str | None = None) -> bool:
    """Check entire pod's status, should be ready only when all containers are ready."""
    settings = get_current_settings()
    namespace = namespace or settings.test_execution_namespace

    # get pod status
    res: ApplyResult = v1_core_api.read_namespaced_pod(
        name=pod_name, namespace=namespace, async_req=True
    )  # type: ignore
    pod = await asyncio.to_thread(res.get)

    # pod conditions: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-conditions
    conditions = pod.status.conditions or []
    for condition in conditions:
        if condition.type.lower() == "ready" and condition.status.lower() == "true":
            return True
    return False


async def wait_for_pod(pod_name: str, max_retries: int = 20, wait_interval: int = 5) -> None:
    """Polls pod to check for readiness"""
    for attempt in range(max_retries):
        if await is_pod_ready(pod_name):
            logger.debug(f"pod ({pod_name}) is ready.")
            return
        logger.debug(f"pod ({pod_name}) is not ready. retry..")
        await asyncio.sleep(wait_interval)

    raise CactusOrchestratorException(f"{pod_name} failed to start.")


@async_k8s_api_retry()
async def add_ingress_rule(svc_name: str) -> None:
    """Updates the Ingress definition to include new path to to service (svc_name)."""

    res: ApplyResult = v1_net_api.read_namespaced_ingress(
        name=get_current_settings().test_execution_ingress_name,
        namespace=get_current_settings().test_execution_namespace,
        async_req=True,
    )  # type: ignore
    ingress = await asyncio.to_thread(res.get)

    http_rule = ingress.spec.rules[0].http
    new_rule = client.V1HTTPIngressPath(
        path=DEFAULT_INGRESS_PATH_FORMAT.format(svc_name=svc_name),
        path_type="Prefix",
        backend=client.V1IngressBackend(
            service=client.V1IngressServiceBackend(
                name=svc_name,
                port=client.V1ServiceBackendPort(number=get_current_settings().teststack_service_port),
            )
        ),
    )

    http_rule.paths.append(new_rule)
    res = v1_net_api.patch_namespaced_ingress(
        get_current_settings().test_execution_ingress_name,
        get_current_settings().test_execution_namespace,
        ingress,
        async_req=True,
    )  # type: ignore
    await asyncio.to_thread(res.get)

    logger.info(f"Ingress rule added for {svc_name}.")
