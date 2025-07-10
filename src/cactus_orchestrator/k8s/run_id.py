import shortuuid
from envoy_schema.server.schema.uri import DeviceCapabilityUri

from cactus_orchestrator.model import User
from cactus_orchestrator.settings import CLONED_RESOURCE_NAME_FORMAT, TEST_EXECUTION_URL_FORMAT, get_current_settings


def generate_static_test_stack_id(user: User) -> str:
    """Given a user - calculate the static value for test_stack_id that will be used if user.is_static_uri is set
    when spawning a new test run"""
    return f"static-{user.user_id}"


def generate_dynamic_test_stack_id() -> str:
    """Calculate a suitable random "dynamic" value for test_stack_id that will be used if user.is_static_uri is False"""
    return shortuuid.uuid().lower()


def generate_envoy_dcap_uri(test_stack_id: str) -> str:
    """Given a test_stack_id - return the URI link to the underlying envoy utility server DeviceCapability"""
    svc_name = CLONED_RESOURCE_NAME_FORMAT.format(
        resource_name=get_current_settings().template_service_name, uuid=test_stack_id
    )
    return (
        TEST_EXECUTION_URL_FORMAT.format(fqdn=get_current_settings().test_execution_fqdn, svc_name=svc_name)
        + DeviceCapabilityUri
    )
