from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import pkcs12

from cactus_orchestrator.k8s.certificate.create import (
    calculate_rfc5280_subject_key_identifier_method_2,
    generate_client_p12_ec,
)
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair


@pytest.mark.parametrize(
    "private_key, expected_ski",
    [
        (
            b"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBN1/lJK6hmijn2voBrkup50oNiLl+z0q9kHb94bvwGaoAoGCCqGSM49
AwEHoUQDQgAEdN+Y8gW5qN2kOvrcP1DQpabQ9fDQhy5qyCk+fXqVX2jCtyDx7MY9
6iM/ZxHacJKcImF78IA8aXdybC8vRL+fzA==
-----END EC PRIVATE KEY-----
""",
            bytes([0x41, 0x59, 0x30, 0xDF, 0xA2, 0x97, 0x01, 0x6C]),
        ),
        (
            b"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIItAzpM90Q4q6SIQBjWO/lcJ3zke1ZmZ9+OEH7FWJgvaoAoGCCqGSM49
AwEHoUQDQgAEbXEg6p7zNEIVBUjnAXvzfGqsa2ZNn+UNvbT+zXbw/CfMNwZDWhLd
ioiRMijNGm8WlVnFzjPU8XqpaKypul+oPQ==
-----END EC PRIVATE KEY-----
""",
            bytes([0x40, 0xDF, 0xCB, 0x43, 0x60, 0x93, 0x13, 0x0E]),
        ),
    ],
)
def test_calculate_rfc5280_subject_key_identifier_method_2(private_key: bytes, expected_ski: bytes):
    """The test cases are derived from openssl examples using:

    openssl ec -in "$key_file" -pubout -outform DER -out "$pub_file"
    local sha1_hash=$(openssl dgst -sha1 -binary "$pub_file" | xxd -p)
    echo "4${sha1_hash:(-15)}"

    """
    ec_private_key = serialization.load_pem_private_key(private_key, password=None)
    actual = calculate_rfc5280_subject_key_identifier_method_2(ec_private_key.public_key())
    assert isinstance(actual, bytes)
    assert actual == expected_ski


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

    # Check that the new cert is signed by mica
    mica_public_key = mica_cert.public_key()
    mica_public_key.verify(cl_cert.signature, cl_cert.tbs_certificate_bytes, ec.ECDSA(cl_cert.signature_hash_algorithm))
    assert (
        cl_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        == mica_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.key_identifier
    )


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
