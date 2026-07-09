import hashlib
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from pyasn1.codec.der import encoder
from pyasn1.type import namedtype, univ

# IEEE 2030.5:2018 Section 6.11.7 certificate policy OIDs
OID_DEV_GENERIC = "1.3.6.1.4.1.40732.1.1"
OID_DEV_POST_MANUFACTURE = "1.3.6.1.4.1.40732.1.3"
OID_POLICY_TEST = "1.3.6.1.4.1.40732.2.1"
OID_POLICY_COMMERCIAL = "1.3.6.1.4.1.40732.2.3"

# RFC 4108 id-on-hardwareModuleName, carried as an otherName in the SubjectAlternativeName
OID_ID_ON_HARDWARE_MODULE_NAME = "1.3.6.1.5.5.7.8.4"

ORG_COUNTRY = "AU"
ORG_NAME = "CACTUS"

# Per-chain EE certificate policy sets (NEPKI profiles).
DEVICE_EE_POLICIES = [OID_DEV_GENERIC, OID_DEV_POST_MANUFACTURE, OID_POLICY_TEST]
AGGREGATOR_EE_POLICIES = [OID_DEV_GENERIC, OID_POLICY_COMMERCIAL]


class HardwareModuleName(univ.Sequence):
    """RFC 4108 HardwareModuleName ::= SEQUENCE { hwType OBJECT IDENTIFIER, hwSerialNum OCTET STRING }"""

    componentType = namedtype.NamedTypes(  # noqa: N815
        namedtype.NamedType("hwType", univ.ObjectIdentifier()),
        namedtype.NamedType("hwSerialNum", univ.OctetString()),
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


def _hardware_module_name_san_entry(user_pen: int, cert_identifier: str) -> x509.OtherName:
    """Build the RFC 4108 id-on-hardwareModuleName otherName: PEN-derived hwType, hwSerialNum 'cactus-<identifier>'."""
    hmn = HardwareModuleName()
    hmn.setComponentByName("hwType", univ.ObjectIdentifier(f"1.3.6.1.4.1.{user_pen}.1.1.1"))
    hmn.setComponentByName("hwSerialNum", univ.OctetString(f"cactus-{cert_identifier}".encode()))
    return x509.OtherName(type_id=ObjectIdentifier(OID_ID_ON_HARDWARE_MODULE_NAME), value=encoder.encode(hmn))


def _generate_signed_client_certificate(
    issuer_key: CertificateIssuerPrivateKeyTypes,
    issuer_cert: x509.Certificate,
    user_pen: int,
    cert_identifier: str,
    subject: x509.Name,
    policy_oids: list[str],
    extended_key_usage: list[x509.ObjectIdentifier] | None = None,
    san_critical: bool = True,
    extra_san_general_names: list[x509.GeneralName] | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate an ECDSA-based EE certificate (2030.5 profile) signed by issuer_key/issuer_cert.

    The SAN always carries the mandatory 2030.5 id-on-hardwareModuleName otherName; extra_san_general_names are appended
    (e.g. a dNSName for the aggregator's whitelisted notification domain). The device and aggregator chains differ on
    subject, certificate policies, ExtendedKeyUsage and SAN criticality - the per-chain wrappers supply those.

    Returns a tuple of (private_key, signed_cert).
    """
    # Use ECC key compatible with TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    client_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())

    csr: x509.CertificateSigningRequest = (
        x509.CertificateSigningRequestBuilder().subject_name(subject).sign(client_key, hashes.SHA256())
    )

    if not_before is None:
        not_before = issuer_cert.not_valid_before_utc + timedelta(seconds=1)
    if not_after is None:
        not_after = issuer_cert.not_valid_after_utc - timedelta(seconds=1)

    # Subject key identifier
    ski = x509.SubjectKeyIdentifier(calculate_rfc5280_subject_key_identifier_method_2(client_key.public_key()))

    # Authority key identifier
    issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value)

    # Certificate policies
    policies = x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier(oid), []) for oid in policy_oids])

    # Subject Alternative Name — 2030.5 hardwareModuleName otherName plus any caller-supplied entries (e.g. dNSName)
    san_general_names: list[x509.GeneralName] = [_hardware_module_name_san_entry(user_pen, cert_identifier)]
    if extra_san_general_names:
        san_general_names.extend(extra_san_general_names)
    san = x509.SubjectAlternativeName(san_general_names)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(ski, critical=False)
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
    )

    if extended_key_usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage(extended_key_usage), critical=False)

    builder = (
        builder.add_extension(policies, critical=True)
        .add_extension(san, critical=san_critical)
        .add_extension(aki, critical=False)
    )

    # Sign with CA key
    client_cert: x509.Certificate = builder.sign(issuer_key, hashes.SHA256())

    return client_key, client_cert


def generate_device_certificate(
    mica_key: CertificateIssuerPrivateKeyTypes,
    mica_cert: x509.Certificate,
    user_pen: int,
    cert_identifier: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a device EE certificate signed by the Device MICA. Returns (private_key, signed_cert)."""
    return _generate_signed_client_certificate(
        mica_key,
        mica_cert,
        user_pen,
        cert_identifier,
        subject=x509.Name([]),  # Blank subject as per the 2030.5 device profile
        policy_oids=DEVICE_EE_POLICIES,
        san_critical=True,
        not_before=not_before,
        not_after=not_after,
    )


def generate_aggregator_certificate(
    ica_key: CertificateIssuerPrivateKeyTypes,
    ica_cert: x509.Certificate,
    user_pen: int,
    cert_identifier: str,
    domain: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate an aggregator EE certificate signed by the Aggregator ICA, carrying a dNSName SAN for the aggregator's
    whitelisted notification domain (used by the utility server to match the webhook host during notification mTLS).
    Returns (private_key, signed_cert)."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, ORG_COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, cert_identifier),
        ]
    )
    return _generate_signed_client_certificate(
        ica_key,
        ica_cert,
        user_pen,
        cert_identifier,
        subject=subject,
        policy_oids=AGGREGATOR_EE_POLICIES,
        extended_key_usage=[ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
        san_critical=False,  # services profile: non-critical SAN
        extra_san_general_names=[x509.DNSName(domain)],
        not_before=not_before,
        not_after=not_after,
    )
