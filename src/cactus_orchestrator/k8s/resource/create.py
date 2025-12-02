"""Resource construction via cloning of 'template' resources."""

import asyncio
import logging
from multiprocessing.pool import ApplyResult

from kubernetes import client
from kubernetes.client import V1EnvVar, V1StatefulSet

from cactus_orchestrator.k8s.resource import RunResourceNames, TemplateResourceNames, async_k8s_api_retry
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
async def clone_service(template_names: TemplateResourceNames, run_names: RunResourceNames) -> None:
    res: ApplyResult = v1_core_api.read_namespaced_service(
        name=template_names.service,
        namespace=template_names.namespace,
        async_req=True,
    )  # type: ignore
    existing = await asyncio.to_thread(res.get)

    new_service = client.V1Service(
        api_version=existing.api_version,
        kind=existing.kind,
        metadata=client.V1ObjectMeta(name=run_names.service),
        spec=client.V1ServiceSpec(
            selector={"app": run_names.app_label},
            ports=existing.spec.ports,
        ),
    )

    # Create the new service
    res = v1_core_api.create_namespaced_service(
        namespace=get_current_settings().test_execution_namespace, body=new_service, async_req=True
    )  # type: ignore
    await asyncio.to_thread(res.get)
    logger.info(f"New service {run_names.service} created successfully!")


@async_k8s_api_retry()
async def clone_statefulset(template_names: TemplateResourceNames, run_names: RunResourceNames) -> None:
    res: ApplyResult = v1_app_api.read_namespaced_stateful_set(
        name=template_names.stateful_set,
        namespace=template_names.namespace,
        async_req=True,
    )  # type: ignore
    existing: V1StatefulSet = await asyncio.to_thread(res.get)

    # Rework the discovered spec into a new spec that's specific to the new service/labels
    new_spec = existing.spec
    if new_spec is None:
        raise CactusOrchestratorException(
            f"{template_names.namespace} {template_names.stateful_set} - missing top level spec"
        )
    new_spec.service_name = run_names.service
    if new_spec.selector.match_labels is None:
        new_spec.selector.match_labels = {"app": run_names.app_label}
    else:
        new_spec.selector.match_labels["app"] = run_names.app_label
    if new_spec.template.metadata is None:
        raise CactusOrchestratorException(
            f"{template_names.namespace} {template_names.stateful_set} - missing spec.template.metadata"
        )
    if new_spec.template.metadata.labels is None:
        new_spec.template.metadata.labels = {"app": run_names.app_label}
    else:
        new_spec.template.metadata.labels["app"] = run_names.app_label

    # We will need to also inject the HREF_PREFIX env variable for the "envoy" container to ensure that all generated
    # hrefs properly include the prefix such that /edev will be encoded as /envoy-svc-abc123/edev
    href_env = V1EnvVar(name="HREF_PREFIX", value=f"/{run_names.service}", value_from=None)
    if new_spec.template.spec is None:
        raise CactusOrchestratorException(
            f"{template_names.namespace} {template_names.stateful_set} - missing template spec"
        )
    update_containers = [c for c in new_spec.template.spec.containers if c.name in {"envoy", "taskiq_worker"}]
    if len(update_containers) != 2:
        raise CactusOrchestratorException(
            f"{template_names.namespace} {template_names.stateful_set} - Expected 2 but found {len(update_containers)}"
            + " envoy/taskiq_worker containers."
        )
    for container_to_update in update_containers:
        if container_to_update.env is None:
            container_to_update.env = [href_env]
        else:
            container_to_update.env.append(href_env)

    new_set = V1StatefulSet(
        api_version=existing.api_version,
        kind=existing.kind,
        metadata=client.V1ObjectMeta(name=run_names.stateful_set),
        spec=new_spec,
    )

    res = v1_app_api.create_namespaced_stateful_set(
        body=new_set, namespace=get_current_settings().test_execution_namespace, async_req=True
    )  # type: ignore
    await asyncio.to_thread(res.get)
    logger.info(f"New StatefulSet {run_names.stateful_set} created successfully!")


async def is_pod_ready(run_names: RunResourceNames) -> bool:
    """Check entire pod's status, should be ready only when all containers are ready."""
    # get pod status
    res: ApplyResult = v1_core_api.read_namespaced_pod(
        name=run_names.pod, namespace=run_names.namespace, async_req=True
    )  # type: ignore
    pod = await asyncio.to_thread(res.get)

    # pod conditions: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-conditions
    conditions = pod.status.conditions or []
    for condition in conditions:
        if condition.type.lower() == "ready" and condition.status.lower() == "true":
            return True
    return False


async def wait_for_pod(run_names: RunResourceNames, max_retries: int = 20, wait_interval: int = 5) -> None:
    """Polls pod to check for readiness"""
    for attempt in range(max_retries):
        try:
            if await is_pod_ready(run_names):
                logger.debug(f"attempt #{attempt}: pod ({run_names.pod}) is ready.")
                return
            logger.debug(f"attempt #{attempt}:pod ({run_names.pod}) is not ready. retry..")
        except Exception as exc:
            logger.error(f"attempt #{attempt}:Exception while checking is_pod_ready", exc_info=exc)

        await asyncio.sleep(wait_interval)

    raise CactusOrchestratorException(f"{run_names.pod} failed to start.")


@async_k8s_api_retry()
async def add_ingress_rule(run_names: RunResourceNames) -> None:
    """Updates the Ingress definition to include new path to to service (svc_name)."""

    res: ApplyResult = v1_net_api.read_namespaced_ingress(
        name=run_names.ingress,
        namespace=run_names.namespace,
        async_req=True,
    )  # type: ignore
    ingress = await asyncio.to_thread(res.get)

    http_rule = ingress.spec.rules[0].http
    new_rule = client.V1HTTPIngressPath(
        path=DEFAULT_INGRESS_PATH_FORMAT.format(svc_name=run_names.service),
        path_type="Prefix",
        backend=client.V1IngressBackend(
            service=client.V1IngressServiceBackend(
                name=run_names.service,
                port=client.V1ServiceBackendPort(number=get_current_settings().teststack_service_port),
            )
        ),
    )

    http_rule.paths.append(new_rule)
    res = v1_net_api.patch_namespaced_ingress(
        run_names.ingress,
        run_names.namespace,
        ingress,
        async_req=True,
    )  # type: ignore
    await asyncio.to_thread(res.get)

    logger.info(f"Ingress rule added for {run_names.service}.")
