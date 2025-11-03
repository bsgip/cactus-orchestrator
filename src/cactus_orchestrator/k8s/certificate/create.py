from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ObjectIdentifier
from pyasn1.codec.der import encoder
from pyasn1.type import namedtype, univ

VALIDITY_DAYS = 365


class ServiceProviderIdentifier(univ.Sequence):
    """ASN.1 Structure 2030.5"""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("oid", univ.ObjectIdentifier()),
        namedtype.NamedType("value", univ.OctetString()),
    )


def generate_client_p12_ec(
    mica_key: CertificateIssuerPrivateKeyTypes,
    mica_cert: x509.Certificate,
    mca_cert: x509.Certificate,
    client_common_name: str,
    p12_password: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
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
        not_after = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    # Subject key identifier
    ski = x509.SubjectKeyIdentifier.from_public_key(client_key.public_key())

    # Authority key identifier
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(mica_key.public_key())

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
        .issuer_name(mica_cert.subject)
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
        .sign(mica_key, hashes.SHA256())
    )

    # Bundle private key and certificate in PKCS#12 (PFX)
    pfx_data: bytes = pkcs12.serialize_key_and_certificates(
        name=client_common_name.encode(),
        key=client_key,
        cert=client_cert,
        cas=[mica_cert, mca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode()),
    )

    return pfx_data, client_cert
