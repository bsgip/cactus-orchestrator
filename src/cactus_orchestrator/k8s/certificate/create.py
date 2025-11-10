import hashlib
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
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


def calculate_rfc5280_subject_key_identifier_method_2(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Implements RFC 5280 4.2.1.2 Subject Key Identifier Method 2"""

    # The keyIdentifier is composed of a four-bit type field with
    # the value 0100 followed by the least significant 60 bits of
    # the SHA-1 hash of the value of the BIT STRING
    # subjectPublicKey (excluding the tag, length, and number of
    # unused bits).

    # The method should match the following openssl snippets
    # openssl ec -in "$key_file" -pubout -outform DER -out "$pub_file"
    # local sha1_hash=$(openssl dgst -sha1 -binary "$pub_file" | xxd -p)
    # echo "4${sha1_hash:(-15)}"

    der_bytes = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    sha1_hash = hashlib.sha1(der_bytes, usedforsecurity=False).digest()

    # Need the least significant 60 bits - we do this by grabbing 7 bytes (56 bits) and then manipulating the 8th byte
    most_significant_byte = 0x40 | (sha1_hash[-8] & 0x0F)  # Take the bottom 4 bits and then write 0100 for the top 4
    return bytes([most_significant_byte]) + sha1_hash[-7:]


def generate_client_p12_ec(
    mica_key: CertificateIssuerPrivateKeyTypes,
    mica_cert: x509.Certificate,
    cert_common_name: str,
    cert_identifier: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate an ECDSA-based signed cert for a client that is signed by mica_key/mica_cert

    Returns a tuple of (private_key, signed_cert).
    """
    # Use ECC key compatible with TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    client_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())

    # Create CSR using ECC key
    csr: x509.CertificateSigningRequest = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cert_common_name)]))
        .sign(client_key, hashes.SHA256())
    )

    if not_before is None:
        not_before = mica_cert.not_valid_before_utc + timedelta(seconds=1)
    if not_after is None:
        not_after = mica_cert.not_valid_after_utc - timedelta(seconds=1)

    # Subject key identifier
    ski = x509.SubjectKeyIdentifier(calculate_rfc5280_subject_key_identifier_method_2(client_key.public_key()))

    # Authority key identifier
    issuer_ski = mica_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value)

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
    spi.setComponentByName("value", univ.OctetString(cert_identifier.encode()))
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

    return client_key, client_cert
