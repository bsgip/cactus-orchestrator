from kubernetes import config, client
from pydantic_settings import BaseSettings


POD_FQDN_FORMAT = "{pod_name}.{svc_name}.{namespace}.svc.cluster.local"
TLS_SERVER_SECRET_NAME_FORMAT = "tls-server-{domain}"
TLS_CA_SECRET_NAME_FORMAT = "tls-ca-{ingress_name}"
CLONED_RESOURCE_NAME_FORMAT = "{resource_name}-{uuid}"
DEFAULT_INGRESS_PATH_FORMAT = "/{svc_name}/(.*)"
TEST_CLIENT_P12_PASSWORD = "abc"  # TODO: temporary


def load_k8s_config():
    """Loads the Kubernetes configuration."""
    try:
        config.load_incluster_config()  # If running inside a cluster
    except config.ConfigException:
        config.load_kube_config()  # If running locally


class K8sManagerException(Exception): ...  # noqa: E701


#  Kubernetes API clients
v1_core_api = client.CoreV1Api()
v1_app_api = client.AppsV1Api()
v1_net_api = client.NetworkingV1Api()
api_client = client.ApiClient()


class K8sManagerSettings(BaseSettings):
    # management
    management_namespace: str = "management"

    # testing
    testing_namespace: str = "test_pods"
    testing_ingress_name: str = "test-pods-ingress"
    envoy_service_port: int = 80
    template_service_name: str = "envoy-svc"
    template_app_name: str = "envoy"
    template_statefulset_name: str = "envoy-set"

    # certificates
    tls_ca_certificate_generic_secret_name: str = (
        "tls-ca-certificate"  # A Generic type secret. This is CA cert used by ingress
    )
    # A TLS type secret. This is the same CA cert along with its key, to be used for signing.
    tls_ca_tls_secret_name: str = "tls-ca-cert-key-pair"


main_settings = K8sManagerSettings()
