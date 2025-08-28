from typing import Callable

from datetime import datetime, timedelta, timezone

from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ObjectIdentifier

from cactus_orchestrator import settings

VALIDITY_DAYS = 365


class ServiceProviderIdentifier(univ.Sequence):
    """ASN.1 Structure 2030.5"""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("oid", univ.ObjectIdentifier()),
        namedtype.NamedType("value", univ.OctetString()),
    )


def generate_client_p12(
    ca_key: CertificateIssuerPrivateKeyTypes,
    ca_cert: x509.Certificate,
    client_common_name: str,
    p12_password: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[bytes, x509.Certificate]:
    """Determines which certificate generation algorithm to use based on key and performs generation

    Args:
        ca_key: private key used for certificate signing
        ca_cert: CA certificate used for creating device/aggregator certificate
        client_common_name: used as part of subject name in cert
        p12_password: for the unpacking of the p12 bundle

    Returns:
        p12 bundle and x509 certificate

    Raises:
        CactusOrchestratorException: if unsupported encryption type provided for private key.
            Needs to be either RSA or Elliptic-Curve
    """
    generate_fn: Callable | None = None
    if isinstance(ca_key, ec.EllipticCurvePrivateKey):
        generate_fn = generate_client_p12_ec
    elif isinstance(ca_key, rsa.RSAPrivateKey):
        generate_fn = generate_client_p12_rsa
    else:
        raise settings.CactusOrchestratorException(
            "Unsupported encryption type private key provided. Needs to be either RSA or EC"
        )

    return generate_fn(
        ca_cert=ca_cert,
        ca_key=ca_key,
        client_common_name=client_common_name,
        p12_password=p12_password,
        not_before=not_before,
        not_after=not_after,
    )


def generate_client_p12_rsa(
    ca_key: CertificateIssuerPrivateKeyTypes,
    ca_cert: x509.Certificate,
    client_common_name: str,
    p12_password: str,
    not_before: datetime | None,
    not_after: datetime | None,
) -> tuple[bytes, x509.Certificate]:
    """Generate a signed cert for client in base64 encoded pcks#12 format.
    Returns a tuple of (p12 bytes, x509.Certificate).
    """
    # Generate a new client private key
    client_key: rsa.RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create CSR
    csr: x509.CertificateSigningRequest = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_common_name)]))
        .sign(client_key, hashes.SHA256())
    )

    if not_before is None:
        not_before = datetime.now(timezone.utc)
    if not_after is None:
        not_after = datetime.now(timezone.utc) + timedelta(days=VALIDITY_DAYS)

    # Sign it with the CA's key to generate cert
    client_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Bundle it with key: PKCS#12 (PFX) format
    pfx_data: bytes = pkcs12.serialize_key_and_certificates(
        name=client_common_name.encode(),
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode()),
    )

    return pfx_data, client_cert


def generate_client_p12_ec(
    ca_key: CertificateIssuerPrivateKeyTypes,
    ca_cert: x509.Certificate,
    client_common_name: str,
    p12_password: str,
    not_before: datetime | None,
    not_after: datetime | None,
) -> tuple[bytes, x509.Certificate]:
    """Generate an ECDSA-based signed cert for client in base64 encoded PKCS#12 format.
    Returns a tuple of (p12 bytes, x509.Certificate).
    """
    # Use ECC key compatible with TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    client_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())

    # Create CSR using ECC key
    csr: x509.CertificateSigningRequest = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_common_name)]))
        .sign(client_key, hashes.SHA256())
    )

    if not_before is None:
        not_before = datetime.now(timezone.utc)
    if not_after is None:
        not_after = datetime.max

    # Subject key identifier
    ski = x509.SubjectKeyIdentifier.from_public_key(client_key.public_key())

    # Authority key identifier
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())

    # Certificate policies
    policies = x509.CertificatePolicies(
        [
            x509.PolicyInformation(ObjectIdentifier("1.3.6.1.4.1.40732.1.1"), []),
            x509.PolicyInformation(ObjectIdentifier("1.3.6.1.4.1.28457.1.1"), []),
        ]
    )

    # Create DER encoded value
    spi = ServiceProviderIdentifier()
    spi.setComponentByName("oid", univ.ObjectIdentifier("1.3.6.1.4.1.40732.3.1.1"))
    spi.setComponentByName("value", univ.OctetString(b"cactus-device-00001"))
    der_value = encoder.encode(spi)

    # Subject Alternative Name — placeholder for `otherName` ASN.1 value
    san = x509.SubjectAlternativeName([x509.OtherName(type_id=ObjectIdentifier("1.3.6.1.5.5.7.8.4"), value=der_value)])

    # Sign with CA key
    client_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(aki, critical=False)
        .add_extension(policies, critical=True)
        .add_extension(san, critical=True)
        .add_extension(ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # Bundle private key and certificate in PKCS#12 (PFX)
    pfx_data: bytes = pkcs12.serialize_key_and_certificates(
        name=client_common_name.encode(),
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode()),
    )

    return pfx_data, client_cert
