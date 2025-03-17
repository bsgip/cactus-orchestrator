import base64


from kubernetes import client
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes

from cactus.harness_orchestrator.settings import (
    main_settings,
    v1_core_api,
)


class SecretString:
    def __init__(self, secret: str):
        self._secret = secret

    def __str__(self) -> str:
        return "REDACTED"

    def __repr__(self) -> str:
        return "SecretString(REDACTED)"

    def reveal(self) -> str:
        """Explicitly return"""
        return self._secret


def fetch_certificate_key_pair(
    secret_name: str, namespace: str | None = None, passphrase_secret: SecretString | None = None
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """
    Reads a PEM certificate and private key from a 'kubernetes.io/tls' type secret.

    Args:
        secret_name (str): The name of the K8s secret.
        namespace (str | None): The namespace where the secret is located. Defaults to the testing namespace.
        passphrase_secret (str | None): Optional passphrase to decrypt the private key if it is encrypted.

    Returns:
        tuple[x509.Certificate, SupportedPrivateKeyType]:
            A tuple containing the certificate and private key.
    """
    namespace = namespace or main_settings.testing_namespace

    # Read secret
    secret: client.V1Secret = v1_core_api.read_namespaced_secret(secret_name, namespace=namespace)

    # Decode b64 encoded cert and key
    crt_bytes = base64.b64decode(secret.data["tls.crt"])
    key_bytes = base64.b64decode(secret.data["tls.key"])

    # Deserialise
    certificate = x509.load_pem_x509_certificate(crt_bytes, default_backend())
    private_key = serialization.load_pem_private_key(
        key_bytes,
        password=passphrase_secret.encode() if passphrase_secret else None,
        backend=default_backend(),
    )

    return certificate, private_key
