# mypy: ignore-errors
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from kubernetes import client

from cactus_orchestrator.settings import TLS_SERVER_SECRET_NAME_FORMAT, main_settings, v1_core_api, v1_net_api


def extract_domain_from_cert(cert_data: bytes) -> str:
    """Extracts the domain from a certificate using SAN or CN as fallback."""

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Try to get the Subject Alternative Name (SAN)
    try:
        san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_extension.value.get_values_for_type(x509.DNSName)
        if dns_names:
            return dns_names[0]  # Use the first SAN entry
    except x509.ExtensionNotFound:
        pass  # SAN not found, fallback to CN

    # Fallback to CN
    attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return attr.decode() if isinstance(attr, bytes) else attr


def create_or_update_k8s_tls_secret(
    *, secret_name: str, cert_data: bytes, namespace: str, key_data: bytes | None = None
) -> None:
    """Creates or updates a Kubernetes TLS secret."""

    data = {"tls.crt": base64.b64encode(cert_data).decode()}

    if key_data is not None:
        data["tls.key"] = base64.b64encode(cert_data).decode()

    # Define the TLS secret
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name, namespace=namespace),
        type="kubernetes.io/tls",
        data=data,
    )

    try:
        v1_core_api.create_namespaced_secret(namespace, secret)
    except client.exceptions.ApiException as exc:
        if exc.status == 409:  # Conflict - secret already exists, so we update it
            v1_core_api.replace_namespaced_secret(secret_name, namespace, secret)
        else:
            raise RuntimeError(f"Failed to create/update TLS secret: {exc}")


def enable_mtls_on_ingress(*, ingress_name: str, ca_secret_name: str, namespace: str) -> None:
    """Patch an Ingress resource to enable client certificate validation using CA cert."""
    # Fetch existing Ingress
    ingress = v1_net_api.read_namespaced_ingress(ingress_name, namespace)

    # Ensure annotations exist
    if ingress.metadata.annotations is None:
        ingress.metadata.annotations = {}

    # Set mTLS annotations
    ingress.metadata.annotations.update(
        {
            "nginx.ingress.kubernetes.io/auth-tls-secret": f"{namespace}/{ca_secret_name}",
            "nginx.ingress.kubernetes.io/auth-tls-verify-client": "on",
            "nginx.ingress.kubernetes.io/auth-tls-verify-depth": "1",
        }
    )

    # Apply the patch
    v1_net_api.replace_namespaced_ingress(ingress_name, namespace, ingress)
    print(f"Ingress '{ingress_name}' updated with mTLS settings.")


def install_server_certificate(
    cert_data: bytes, key_data: bytes, ingress_name: str, namespace: str | None = None
) -> None:
    """Creates a TLS secret and updates the Ingress with it."""
    namespace = namespace or main_settings.test_execution_namespace

    domain = extract_domain_from_cert(cert_data)
    secret_name = TLS_SERVER_SECRET_NAME_FORMAT.format(domain=domain.replace(".", "-"))
    create_or_update_k8s_tls_secret(
        secret_name=secret_name, cert_data=cert_data, key_data=key_data, namespace=namespace
    )

    ingress = v1_net_api.read_namespaced_ingress(ingress_name, namespace)
    if not ingress.spec.tls:
        ingress.spec.tls = []

    # Update existing TLS entry or add a new one
    for entry in ingress.spec.tls:
        if domain in entry.hosts:
            entry.secret_name = secret_name
            break
    else:
        ingress.spec.tls.append(client.V1IngressTLS(hosts=[domain], secret_name=secret_name))

    v1_net_api.patch_namespaced_ingress(ingress_name, namespace, ingress)
