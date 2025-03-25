from kubernetes import config
from pydantic import PostgresDsn, SecretStr
from pydantic_settings import BaseSettings

TEST_CLIENT_P12_PASSWORD = SecretStr("abc")  # TODO: temporary
POD_FQDN_FORMAT = "{pod_name}.{svc_name}.{namespace}.svc.cluster.local"  # TODO: use svc instead.
POD_HARNESS_RUNNER_MANAGEMENT_PORT = 8080  # TODO: tbd
TLS_SERVER_SECRET_NAME_FORMAT = "tls-server-{domain}"
TLS_CA_SECRET_NAME_FORMAT = "tls-ca-{ingress_name}"
CLONED_RESOURCE_NAME_FORMAT = "{resource_name}-{uuid}"
# NOTE: follwing two must be kept similar
DEFAULT_INGRESS_PATH_FORMAT = "/{svc_name}/(.*)"
TESTING_URL_FORMAT = "https://{testing_fqdn}/{svc_name}"
STATEFULSET_POD_NAME_FORMAT = (
    "{statefulset_name}-0"  # TODO: this is the k8s naming scheme of a statefulsets pod, how to better handle?
)
RUNNER_POD_URL = "https://{pod_fqdn}:{pod_port}"  # TODO: use service instead


def load_k8s_config() -> None:
    """Loads the Kubernetes configuration."""
    try:
        config.incluster_config.load_incluster_config()  # If running inside a cluster
    except config.config_exception.ConfigException:
        config.kube_config.load_kube_config()  # If running locally


class HarnessOrchestratorException(Exception): ...  # noqa: E701


class HarnessOrchestratorSettings(BaseSettings):
    # management
    management_namespace: str = "management"
    orchestrator_database_url: PostgresDsn

    # testing
    testing_namespace: str = "testing"
    testing_ingress_name: str = "testing-ingress"
    envoy_service_port: int = 80
    template_service_name: str = "envoy-svc"
    template_app_name: str = "envoy"
    template_statefulset_name: str = "envoy-set"

    # certificates
    tls_ca_certificate_generic_secret_name: str = (
        "tls-ca-certificate"  # A Generic type secret. This is CA cert used by ingress.
    )
    # A TLS type secret. This is the same CA cert along with its key, to be used for signing.
    tls_ca_tls_secret_name: str = "tls-ca-cert-key-pair"
    # tls_server_tls_secret_name: str = "tls-server-secret-pair"
    testing_fqdn: str  # NOTE: we could extract this from the server certs

    # teardown
    teardown_max_lifetime_seconds: int = 86400
    teardown_idle_timeout_seconds: int = 3600


class JWTAuthSettings(BaseSettings):
    jwks_url: str
    issuer: str
    audience: str

    class Config:
        env_prefix = "JWTAUTH_"


main_settings = HarnessOrchestratorSettings()  # type: ignore  [call-arg]
