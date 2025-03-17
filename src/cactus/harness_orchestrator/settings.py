from kubernetes import config, client
from pydantic_settings import BaseSettings


TEST_CLIENT_P12_PASSWORD = "abc"  # TODO: temporary
POD_FQDN_FORMAT = "{pod_name}.{svc_name}.{namespace}.svc.cluster.local"  # TODO: use svc instead.
POD_HARNESS_RUNNER_MANAGEMENT_PORT = 8080  # TODO: tbd
TLS_SERVER_SECRET_NAME_FORMAT = "tls-server-{domain}"
TLS_CA_SECRET_NAME_FORMAT = "tls-ca-{ingress_name}"
CLONED_RESOURCE_NAME_FORMAT = "{resource_name}-{uuid}"
# NOTE: follwing two must be kept similar
DEFAULT_INGRESS_PATH_FORMAT = "/{svc_name}/(.*)"
TESTING_URL_FORMAT = "https://{testing_fqdn}/{svc_name}"


def load_k8s_config():
    """Loads the Kubernetes configuration."""
    try:
        config.load_incluster_config()  # If running inside a cluster
    except config.ConfigException:
        config.load_kube_config()  # If running locally


class K8sManagerException(Exception): ...  # noqa: E701


class K8sManagerSettings(BaseSettings):
    # management
    management_namespace: str = "management"

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


main_settings = K8sManagerSettings()


#  Kubernetes API clients
load_k8s_config()  # NOTE: This needs to be called before instantiating any of the k8s clients
v1_core_api = client.CoreV1Api()
v1_app_api = client.AppsV1Api()
v1_net_api = client.NetworkingV1Api()
api_client = client.ApiClient()
