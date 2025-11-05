from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12

from cactus_orchestrator.k8s.certificate.create import generate_client_p12_ec
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair


def test_generate_client_p12_ec(mca_cert_key_pair, mica_cert_key_pair):
    # Arrange
    mca_cert, mca_key = mca_cert_key_pair
    mica_cert, mica_key = mica_cert_key_pair
    client_common_name = "Test Client"
    p12_password = "testpwd"

    # Act
    pfx_data, cl_cert = generate_client_p12_ec(mica_key, mica_cert, mca_cert, client_common_name, p12_password)

    # Assert
    cl_key, cl_cert2, _ = pkcs12.load_key_and_certificates(pfx_data, p12_password.encode())
    assert isinstance(pfx_data, bytes)
    assert len(pfx_data) > 0
    assert cl_cert.issuer == mica_cert.subject
    assert cl_cert2 is not None
    assert cl_cert2.issuer == mica_cert.subject
    assert isinstance(cl_key, ec.EllipticCurvePrivateKey)

    assert cl_cert.not_valid_after_utc < mica_cert.not_valid_after_utc
    assert cl_cert.not_valid_before_utc > mica_cert.not_valid_before_utc


def test_generate_client_p12_invalid_password(mca_cert_key_pair, mica_cert_key_pair):
    mca_cert, mca_key = mca_cert_key_pair
    mica_cert, mica_key = mica_cert_key_pair
    client_common_name = "Test Client"
    p12_password = ""

    with pytest.raises(ValueError):
        generate_client_p12_ec(mica_key, mica_cert, mca_cert, client_common_name, p12_password)


@patch("cactus_orchestrator.k8s.certificate.fetch.v1_core_api")
@pytest.mark.asyncio
async def test_fetch_certificate_key_pair(mock_v1_core_api, mock_k8s_tls_secret, mock_thread_cls):
    """Test fetching a certificate and key from a mock Kubernetes secret."""

    mock_v1_core_api.read_namespaced_secret.return_value = mock_thread_cls(mock_k8s_tls_secret)

    cert, key = await fetch_certificate_key_pair("test-secret", "test-namespace")

    assert isinstance(cert, x509.Certificate)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
