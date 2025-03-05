from unittest.mock import MagicMock
from datetime import datetime, timedelta, timezone
import base64
import pytest

from kubernetes.client import V1Secret
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes, asymmetric
from cryptography.x509.oid import NameOID


@pytest.fixture(scope="session")
def ca_cert_key_pair():
    ca_key = asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return (ca_cert, ca_key)


@pytest.fixture
def mock_k8s_tls_secret(ca_cert_key_pair):
    cert_pem, cert_key = ca_cert_key_pair
    secret_mock = MagicMock(spec=V1Secret)
    secret_mock.data = {
        "tls.crt": base64.b64encode(
            cert_pem.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
        ).decode(),
        "tls.key": base64.b64encode(
            cert_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode(),
    }
    return secret_mock
