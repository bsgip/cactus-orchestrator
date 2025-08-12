import asyncio
import logging
import re
from dataclasses import dataclass
from functools import wraps
from typing import Awaitable, Callable

import shortuuid
from envoy_schema.server.schema.uri import DeviceCapabilityUri
from kubernetes.client.exceptions import ApiException

from cactus_orchestrator.model import User
from cactus_orchestrator.settings import (
    POD_FQDN_FORMAT,
    POD_HARNESS_RUNNER_MANAGEMENT_PORT,
    RUNNER_POD_URL,
    STATEFULSET_POD_NAME_FORMAT,
    TEST_EXECUTION_URL_FORMAT,
    CactusOrchestratorException,
    get_current_settings,
)

logger = logging.getLogger(__name__)


@dataclass
class TemplateResourceNames:
    """Contains all the k8's object IDs associated with a template stack of resource"""

    namespace: str
    service: str  # Name of the K8's service template
    stateful_set: str  # Name of the K8's stateful set
    app_label: str  # Name of the "app" within the template spec -


@dataclass
class RunResourceNames:
    """Contains all the k8's object IDs associated with a Run (these may or may not be running/created)"""

    namespace: str
    service: str  # Name of the k8's service for the associated run (when running)
    stateful_set: str  # Name of the k8's stateful set for the associated run (when running)
    pod: str  # Name of the k8's pod for the associated run (when running)
    pod_fqdn: str  # Fully qualified domain name of the pod
    app_label: str  # Name of the "app" within the run execution spec
    ingress: str  # Name of the ingress resource

    envoy_base_url: str  # Base URL of the envoy instance (accessible from OUTSIDE the k8s deployment)
    runner_base_url: str  # Base URL of the runner (accessible only within k8s deployment)


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
                        raise CactusOrchestratorException(
                            f"Failed action: {func.__name__}. Last API error: {exc.status} {exc.reason}"
                        )
                    else:
                        logger.info(f"Call to {func.__name__} failing silently")
                        return None
            return None

        return async_retry

    return decorator


def get_template_names(csip_aus_version: str) -> TemplateResourceNames:
    """Returns the k8's object identifiers for the template associated with the specified CSIP Aus version"""
    settings = get_current_settings()
    version = csip_aus_version_to_k8s_id(csip_aus_version)
    return TemplateResourceNames(
        namespace=settings.teststack_templates_namespace,
        service=settings.template_service_name_prefix + version,
        stateful_set=settings.template_statefulset_name_prefix + version,
        app_label=settings.template_app_name_prefix + version,
    )


def get_resource_names(uuid: str) -> RunResourceNames:
    """Returns the k8's object identifiers for the executing Run with the specified uuid + csip aus version"""
    settings = get_current_settings()

    svc_name = settings.template_service_name_prefix + uuid
    statefulset_name = settings.template_statefulset_name_prefix + uuid
    app_label = settings.template_app_name_prefix + uuid
    pod_name = STATEFULSET_POD_NAME_FORMAT.format(statefulset_name=statefulset_name)
    pod_fqdn = POD_FQDN_FORMAT.format(pod_name=pod_name, svc_name=svc_name, namespace=settings.test_execution_namespace)

    runner_base_url = RUNNER_POD_URL.format(pod_fqdn=pod_fqdn, pod_port=POD_HARNESS_RUNNER_MANAGEMENT_PORT)
    envoy_base_url = TEST_EXECUTION_URL_FORMAT.format(fqdn=settings.test_execution_fqdn, svc_name=svc_name)

    return RunResourceNames(
        namespace=settings.test_execution_namespace,
        service=svc_name,
        stateful_set=statefulset_name,
        app_label=app_label,
        pod=pod_name,
        pod_fqdn=pod_fqdn,
        ingress=settings.test_execution_ingress_name,
        runner_base_url=runner_base_url,
        envoy_base_url=envoy_base_url,
    )


def generate_envoy_dcap_uri(resources: RunResourceNames) -> str:
    """Given a test_stack_id - return the URI link to the underlying envoy utility server DeviceCapability"""
    return resources.envoy_base_url + DeviceCapabilityUri


def generate_static_test_stack_id(user: User) -> str:
    """Given a user - calculate the static value for test_stack_id that will be used if user.is_static_uri is set
    when spawning a new test run"""
    return f"static-{user.user_id}"


def generate_dynamic_test_stack_id() -> str:
    """Calculate a suitable random "dynamic" value for test_stack_id that will be used if user.is_static_uri is False"""
    return shortuuid.uuid().lower()


K8S_REPLACE_PATTERN = re.compile("[^a-z\\-0-9]")


def csip_aus_version_to_k8s_id(csip_aus_version: str) -> str:
    """Converts a CSIPAusVersion to a compatible kubernetes identifier"""

    if not csip_aus_version:
        raise ValueError(f"Invalid csip_aus_version '{csip_aus_version}'")

    return re.sub(K8S_REPLACE_PATTERN, "-", csip_aus_version.lower())
