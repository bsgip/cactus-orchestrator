from unittest.mock import patch
import pytest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from csip_aus_client_test_harness.harness_orchestrator.k8s_management.certificate.create import generate_client_p12
from csip_aus_client_test_harness.harness_orchestrator.k8s_management.certificate.fetch import (
    fetch_certificate_key_pair,
)


def test_generate_client_p12(ca_cert_key_pair):
    ca_cert, ca_key = ca_cert_key_pair
    client_common_name = "Test Client"
    p12_password = "testpwd"

    pfx_data = generate_client_p12(ca_key, ca_cert, client_common_name, p12_password)

    assert isinstance(pfx_data, bytes)
    assert len(pfx_data) > 0


def test_generate_client_p12_invalid_password(ca_cert_key_pair):
    ca_cert, ca_key = ca_cert_key_pair
    client_common_name = "Test Client"
    p12_password = ""

    with pytest.raises(ValueError):
        generate_client_p12(ca_key, ca_cert, client_common_name, p12_password)


@patch("csip_aus_client_test_harness.harness_orchestrator.k8s_management.certificate.fetch.v1_core_api")
def test_fetch_certificate_key_pair(mock_v1_core_api, mock_k8s_tls_secret):
    """Test fetching a certificate and key from a mock Kubernetes secret."""

    mock_v1_core_api.read_namespaced_secret.return_value = mock_k8s_tls_secret

    cert, key = fetch_certificate_key_pair("test-secret", "test-namespace")

    assert isinstance(cert, x509.Certificate)
    assert isinstance(key, rsa.RSAPrivateKey)
