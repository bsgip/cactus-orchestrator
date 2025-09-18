import logging
import os

from kubernetes import client, config
from pydantic import PostgresDsn
from pydantic_settings import BaseSettings

POD_FQDN_FORMAT = "{pod_name}.{svc_name}.{namespace}.svc.cluster.local"  # TODO: use svc instead.
POD_HARNESS_RUNNER_MANAGEMENT_PORT = 8080  # TODO: tbd
TLS_SERVER_SECRET_NAME_FORMAT = "tls-server-{domain}"  # nosec: Not a password
TLS_CA_SECRET_NAME_FORMAT = "tls-ca-{ingress_name}"  # nosec: Not a password
# NOTE: follwing two must be kept similar
DEFAULT_INGRESS_PATH_FORMAT = "/{svc_name}/(.*)"
TEST_EXECUTION_URL_FORMAT = "https://{fqdn}/{svc_name}"

STATEFULSET_POD_NAME_FORMAT = (
    "{statefulset_name}-0"  # TODO: this is the k8s naming scheme of a statefulsets pod, how to better handle?
)
RUNNER_POD_URL = "http://{pod_fqdn}:{pod_port}"  # TODO: use service instead


logger = logging.getLogger(__name__)


def load_k8s_config() -> None:
    """Loads the Kubernetes configuration."""
    if os.getenv("CACTUS_PYTEST_WITHOUT_KUBERNETES", "").lower() == "true":
        logger.warning("Skipping k8s configuration load...")
        return
    try:
        config.incluster_config.load_incluster_config()  # If running inside a cluster
    except config.config_exception.ConfigException:
        config.kube_config.load_kube_config()  # If running locally


class CactusOrchestratorException(Exception): ...  # noqa: E701


class CactusOrchestratorSettings(BaseSettings):
    # misc
    kubernetes_load_config: bool = True  # just for pytests TODO: find a better way

    # test orchestration
    test_orchestration_namespace: str = "test-orchestration"
    orchestrator_database_url: PostgresDsn

    # test execution
    test_execution_namespace: str = "test-execution"
    test_execution_ingress_name: str = "test-execution-ingress"
    teststack_service_port: int = 80
    test_execution_comms_timeout_seconds: int = 120  # The default timeout to use when making requests to the test stack

    # teststack templates
    teststack_templates_namespace: str = "teststack-templates"
    template_service_name_prefix: str = "envoy-svc-"  # Will be combined with CSIP-Aus Version identifier / uuid
    template_app_name_prefix: str = "envoy-"  # Will be combined with CSIP-Aus Version identifier / uuid
    template_statefulset_name_prefix: str = "envoy-set-"  # Will be combined with CSIP-Aus Version identifier  / uuid

    # certificates
    tls_ca_certificate_generic_secret_name: str = (
        "tls-ca-certificate"  # A Generic type secret. This is CA cert used by ingress.
    )
    # A TLS type secret. This is the same CA cert along with its key, to be used for signing.
    tls_ca_tls_secret_name: str = "tls-ca-cert-key-pair"
    # tls_server_tls_secret_name: str = "tls-server-secret-pair"
    test_execution_fqdn: str  # NOTE: we could extract this from the server certs

    # teardown
    idleteardowntask_enable: bool = True
    idleteardowntask_max_lifetime_seconds: int = 86400
    idleteardowntask_idle_timeout_seconds: int = 3600
    idleteardowntask_repeat_every_seconds: int = 120

    # readiness
    pod_readiness_check_container_name: str = "envoy"


class JWTAuthSettings(BaseSettings):
    jwks_url: str
    issuer: str
    audience: str

    class Config:
        env_prefix = "JWTAUTH_"


_main_settings: CactusOrchestratorSettings | None = None


def get_current_settings() -> CactusOrchestratorSettings:
    global _main_settings
    if not _main_settings:
        _main_settings = CactusOrchestratorSettings()  # type: ignore  [call-arg]
        return _main_settings
    return _main_settings


# NOTE: just for tests, not thread-safe
def _reset_current_settings() -> None:
    global _main_settings
    _main_settings = None


# NOTE: This needs to be called before instantiating any of the k8s clients
load_k8s_config()
v1_core_api = client.CoreV1Api()
v1_app_api = client.AppsV1Api()
v1_net_api = client.NetworkingV1Api()
