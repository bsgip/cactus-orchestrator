from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


VALIDITY_DAYS = 10


def generate_client_p12(
    ca_key: CertificateIssuerPrivateKeyTypes,
    ca_cert: x509.Certificate,
    client_common_name: str,
    p12_password: str,
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

    # Sign it with the CA's key to generate cert
    client_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=VALIDITY_DAYS))
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
