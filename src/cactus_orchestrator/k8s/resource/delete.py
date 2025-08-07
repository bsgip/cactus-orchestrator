import asyncio
import logging
from http import HTTPStatus
from multiprocessing.pool import ApplyResult

from cactus_orchestrator.k8s.resource import RunResourceNames, async_k8s_api_retry
from cactus_orchestrator.settings import (
    DEFAULT_INGRESS_PATH_FORMAT,
    get_current_settings,
    v1_app_api,
    v1_core_api,
    v1_net_api,
)

logger = logging.getLogger(__name__)


@async_k8s_api_retry(ignore_status_code=HTTPStatus.NOT_FOUND, fail_silently=True)
async def delete_service(run_resource_names: RunResourceNames) -> None:
    res: ApplyResult = v1_core_api.delete_namespaced_service(
        run_resource_names.service, namespace=run_resource_names.namespace, async_req=True
    )  # type: ignore

    await asyncio.to_thread(res.get)
    logger.info(f"Service deleted: {run_resource_names.service}")


@async_k8s_api_retry(ignore_status_code=HTTPStatus.NOT_FOUND, fail_silently=True)
async def delete_statefulset(run_resource_names: RunResourceNames) -> None:
    res: ApplyResult = v1_app_api.delete_namespaced_stateful_set(
        run_resource_names.stateful_set, namespace=run_resource_names.namespace, async_req=True
    )  # type: ignore

    await asyncio.to_thread(res.get)
    logger.info(f"Statefulset deleted: {run_resource_names.stateful_set}")


@async_k8s_api_retry()
async def remove_ingress_rule(run_resource_names: RunResourceNames) -> None:

    # Construct the path to remove (same format used in add_ingress_rule)
    target_path = DEFAULT_INGRESS_PATH_FORMAT.format(svc_name=run_resource_names.service)

    # Fetch ingress
    res: ApplyResult = v1_net_api.read_namespaced_ingress(
        name=get_current_settings().test_execution_ingress_name, namespace=run_resource_names.namespace, async_req=True
    )  # type: ignore
    ingress = await asyncio.to_thread(res.get)
    http_rule = ingress.spec.rules[0].http

    # Filter out the target path
    original_length = len(http_rule.paths)
    http_rule.paths = [p for p in http_rule.paths if p.path != target_path]

    # If nothing changed, no need to update
    if len(http_rule.paths) == original_length:
        logger.info(f"No matching ingress rule found for {run_resource_names.service}, no update needed.")
        return

    # Patch the Ingress with the updated paths
    res = v1_net_api.patch_namespaced_ingress(
        name=get_current_settings().test_execution_ingress_name,
        namespace=get_current_settings().test_execution_namespace,
        body=ingress,
        async_req=True,
    )  # type: ignore
    await asyncio.to_thread(res.get)

    logger.info(f"Ingress rule removed for {run_resource_names.service}.")
