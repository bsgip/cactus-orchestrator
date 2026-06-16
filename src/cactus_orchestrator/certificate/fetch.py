"""File-based certificate loading — replaces k8s Secret reads."""

from typing import get_args

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes

from cactus_orchestrator.settings import CactusOrchestratorError


def fetch_certificate_key_pair(
    cert_path: str, key_path: str
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    with open(key_path, "rb") as f:
        key_bytes = f.read()

    certificate = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    private_key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())

    if not isinstance(private_key, tuple(get_args(CertificateIssuerPrivateKeyTypes))):
        raise CactusOrchestratorError(f"Invalid private key type in {key_path}")

    return certificate, private_key


def fetch_certificate_only(cert_path: str) -> x509.Certificate:
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    return x509.load_pem_x509_certificate(cert_bytes, default_backend())
