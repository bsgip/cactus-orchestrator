import logging
import asyncio
from threading import Thread

from http import HTTPStatus

from cactus.harness_orchestrator.k8s_management.resource import async_k8s_api_retry
from cactus.harness_orchestrator.settings import (
    v1_core_api,
    v1_app_api,
    v1_net_api,
    main_settings,
    DEFAULT_INGRESS_PATH_FORMAT,
)


logger = logging.getLogger(__name__)


@async_k8s_api_retry(ignore_status_code=HTTPStatus.NOT_FOUND, fail_silently=True)
async def delete_service(svc_name: str, namespace: str | None = None):
    namespace = namespace or main_settings.testing_namespace
    res: Thread = v1_core_api.delete_collection_namespaced_service(svc_name, namespace=namespace, async_req=True)

    await asyncio.to_thread(res.get)
    logger.info(f"Service deleted: {svc_name}")


@async_k8s_api_retry(ignore_status_code=HTTPStatus.NOT_FOUND, fail_silently=True)
async def delete_statefulset(statefulset_name: str, namespace: str | None = None):
    namespace = namespace or main_settings.testing_namespace
    res: Thread = v1_app_api.delete_namespaced_stateful_set(statefulset_name, namespace=namespace, async_req=True)

    await asyncio.to_thread(res.get)
    logger.info(f"Statefulset deleted: {statefulset_name}")


@async_k8s_api_retry()
async def remove_ingress_rule(svc_name: str, namespace: str | None = None):
    namespace = namespace or main_settings.testing_namespace

    # Construct the path to remove (same format used in add_ingress_rule)
    target_path = DEFAULT_INGRESS_PATH_FORMAT.format(svc_name=svc_name)

    # Fetch ingress
    res: Thread = v1_net_api.read_namespaced_ingress(
        name=main_settings.testing_ingress_name, namespace=namespace, async_req=True
    )
    ingress = await asyncio.to_thread(res.get)
    http_rule = ingress.spec.rules[0].http

    # Filter out the target path
    original_length = len(http_rule.paths)
    http_rule.paths = [p for p in http_rule.paths if p.path != target_path]

    # If nothing changed, no need to update
    if len(http_rule.paths) == original_length:
        logger.info(f"No matching ingress rule found for {svc_name}, no update needed.")
        return

    # Patch the Ingress with the updated paths
    res: Thread = v1_net_api.patch_namespaced_ingress(
        name=main_settings.testing_ingress_name, namespace=main_settings.testing_namespace, body=ingress, async_req=True
    )
    await asyncio.to_thread(res.get)

    logger.info(f"Ingress rule removed for {svc_name}.")
