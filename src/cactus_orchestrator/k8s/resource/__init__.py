import asyncio
import logging
from functools import wraps
from typing import Awaitable, Callable

from kubernetes.client.exceptions import ApiException

from cactus_orchestrator.settings import (
    CLONED_RESOURCE_NAME_FORMAT,
    POD_FQDN_FORMAT,
    STATEFULSET_POD_NAME_FORMAT,
    HarnessOrchestratorException,
    main_settings,
)

logger = logging.getLogger(__name__)


def async_k8s_api_retry[**P, T](
    retries: int = 3, delay: int = 2, ignore_status_code: int | None = None, fail_silently: bool = False
) -> Callable[[Callable[P, Awaitable[T | None]]], Callable[P, Awaitable[T | None]]]:
    """Used to wrap any of the async k8s api requests with retry functionality."""

    def decorator(func: Callable[P, Awaitable[T | None]]) -> Callable[P, Awaitable[T | None]]:
        @wraps(func)
        async def async_retry(*args: P.args, **kwargs: P.kwargs) -> T | None:
            for attempt in range(retries):
                try:
                    return await func(*args, **kwargs)
                except ApiException as exc:
                    if ignore_status_code is not None:
                        if exc.status == ignore_status_code:
                            return None
                    logger.debug(f"[Attempt {attempt+1}] Kubernetes API error: {exc.status} {exc.reason}")
                    if attempt < retries - 1:
                        await asyncio.sleep(delay)
                    elif not fail_silently:
                        raise HarnessOrchestratorException(
                            f"Failed action: {func.__name__}. Last API error: {exc.status} {exc.reason}"
                        )
                    else:
                        logger.info(f"Call to {func.__name__} failing silently")
                        return None
            return None

        return async_retry

    return decorator


# TODO: usage is error prone
def get_resource_names(uuid: str, namespace: str | None = None) -> tuple[str, str, str, str, str]:
    """Returns tuple of names: svc_name, statefulset_name, app_label, pod_name, pod_fqdn"""
    namespace = namespace or main_settings.testing_namespace

    svc_name = CLONED_RESOURCE_NAME_FORMAT.format(resource_name=main_settings.template_service_name, uuid=uuid)
    statefulset_name = CLONED_RESOURCE_NAME_FORMAT.format(
        resource_name=main_settings.template_statefulset_name, uuid=uuid
    )
    app_label = CLONED_RESOURCE_NAME_FORMAT.format(resource_name=main_settings.template_app_name, uuid=uuid)
    pod_name = STATEFULSET_POD_NAME_FORMAT.format(statefulset_name=statefulset_name)
    pod_fqdn = POD_FQDN_FORMAT.format(pod_name=pod_name, svc_name=svc_name, namespace=main_settings.testing_namespace)

    return svc_name, statefulset_name, app_label, pod_name, pod_fqdn
