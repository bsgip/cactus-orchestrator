from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair


def test_generate_client_p12(ca_cert_key_pair):
    # Arrange
    ca_cert, ca_key = ca_cert_key_pair
    client_common_name = "Test Client"
    p12_password = "testpwd"

    # Act
    pfx_data, cl_cert = generate_client_p12(ca_key, ca_cert, client_common_name, p12_password)

    # Assert
    cl_key, cl_cert2, _ = pkcs12.load_key_and_certificates(pfx_data, p12_password.encode())
    assert isinstance(pfx_data, bytes)
    assert len(pfx_data) > 0
    assert cl_cert.issuer == ca_cert.subject
    assert cl_cert2.issuer == ca_cert.subject
    assert isinstance(cl_key, rsa.RSAPrivateKey)


def test_generate_client_p12_invalid_password(ca_cert_key_pair):
    ca_cert, ca_key = ca_cert_key_pair
    client_common_name = "Test Client"
    p12_password = ""

    with pytest.raises(ValueError):
        generate_client_p12(ca_key, ca_cert, client_common_name, p12_password)


@patch("cactus_orchestrator.k8s.certificate.fetch.v1_core_api")
@pytest.mark.asyncio
async def test_fetch_certificate_key_pair(mock_v1_core_api, mock_k8s_tls_secret, mock_thread_cls):
    """Test fetching a certificate and key from a mock Kubernetes secret."""

    mock_v1_core_api.read_namespaced_secret.return_value = mock_thread_cls(mock_k8s_tls_secret)

    cert, key = await fetch_certificate_key_pair("test-secret", "test-namespace")

    assert isinstance(cert, x509.Certificate)
    assert isinstance(key, rsa.RSAPrivateKey)
