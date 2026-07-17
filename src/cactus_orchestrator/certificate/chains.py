from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cactus_orchestrator.certificate.create import (
    ORG_COUNTRY,
    ORG_NAME,
    calculate_rfc5280_subject_key_identifier_method_2,
)

# keyUsage asserted on every CA certificate, matching the NEPKI CA profile (cactus-deploy pki/create-cert.sh)
CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)


def build_ca_cert(
    common_name: str,
    subject_key: ec.EllipticCurvePrivateKey,
    path_length: int | None,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
) -> x509.Certificate:
    """Builds a CA certificate mirroring the structural NEPKI CA profile (cactus-deploy pki/create-cert.sh): a
    C=AU,O=CACTUS,CN=<common_name> subject, critical CA basicConstraints with the supplied pathlen, keyCertSign+cRLSign
    keyUsage and a method-2 subjectKeyIdentifier. issuer=None yields a self-signed root (SERCA); otherwise the cert is
    signed by the issuer and carries the matching authorityKeyIdentifier.

    NOT used to build production chains (that's cactus-deploy pki/create-cert.sh) - this exists for tests and the
    local-dev throwaway PKI (local-dev/generate_dev_pki.py)."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, ORG_COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    issuer_cert, signing_key = issuer if issuer is not None else (None, subject_key)
    ski = x509.SubjectKeyIdentifier(calculate_rfc5280_subject_key_identifier_method_2(subject_key.public_key()))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert is not None else subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .add_extension(ski, critical=False)
    )
    if issuer_cert is not None:
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value), critical=False
        )

    return builder.sign(signing_key, hashes.SHA256())
