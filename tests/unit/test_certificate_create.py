from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyasn1.codec.der import decoder

from cactus_orchestrator.certificate.create import (
    HardwareModuleName,
    generate_aggregator_certificate,
    generate_device_certificate,
)

OID_2030_5_OTHERNAME = x509.ObjectIdentifier("1.3.6.1.5.5.7.8.4")
OID_DEV_GENERIC = x509.ObjectIdentifier("1.3.6.1.4.1.40732.1.1")
OID_DEV_POST_MANUFACTURE = x509.ObjectIdentifier("1.3.6.1.4.1.40732.1.3")
OID_POLICY_TEST = x509.ObjectIdentifier("1.3.6.1.4.1.40732.2.1")
OID_POLICY_COMMERCIAL = x509.ObjectIdentifier("1.3.6.1.4.1.40732.2.3")


def _ext(cert, klass):
    return cert.extensions.get_extension_for_class(klass)


def _san(cert: x509.Certificate) -> x509.SubjectAlternativeName:
    return _ext(cert, x509.SubjectAlternativeName).value


def _hardware_module_name(cert: x509.Certificate) -> HardwareModuleName:
    other_name = next(n for n in _san(cert).get_values_for_type(x509.OtherName) if n.type_id == OID_2030_5_OTHERNAME)
    decoded, _ = decoder.decode(other_name.value, asn1Spec=HardwareModuleName())
    return decoded


def _policy_oids(cert: x509.Certificate) -> list[x509.ObjectIdentifier]:
    return [p.policy_identifier for p in _ext(cert, x509.CertificatePolicies).value]


def test_device_certificate_profile(mica_cert_key_pair):
    mica_cert, mica_key = mica_cert_key_pair

    _, cert = generate_device_certificate(mica_key, mica_cert, 64, "rg-1-Device-1")

    # Blank subject, no DNS SAN, no EKU - matches the NEPKI device profile
    assert cert.subject == x509.Name([])
    assert cert.issuer == mica_cert.subject
    assert _san(cert).get_values_for_type(x509.DNSName) == []
    assert _ext(cert, x509.SubjectAlternativeName).critical is True
    assert _policy_oids(cert) == [OID_DEV_GENERIC, OID_DEV_POST_MANUFACTURE, OID_POLICY_TEST]
    try:
        _ext(cert, x509.ExtendedKeyUsage)
        raise AssertionError("device cert must not carry an ExtendedKeyUsage")
    except x509.ExtensionNotFound:
        pass

    hmn = _hardware_module_name(cert)
    assert str(hmn["hwType"]) == "1.3.6.1.4.1.64.1.1.1"  # PEN-derived (user_pen=64)
    assert bytes(hmn["hwSerialNum"]) == b"cactus-rg-1-Device-1"


def test_aggregator_certificate_profile(mica_cert_key_pair):
    # mica_cert_key_pair stands in for the Aggregator ICA (it only needs a SubjectKeyIdentifier to issue from)
    ica_cert, ica_key = mica_cert_key_pair
    domain = "aggregator1.example.com"

    _, cert = generate_aggregator_certificate(ica_key, ica_cert, 64, "rg-1-Aggregator-1", domain)

    # Populated subject, dNSName SAN (non-critical), client+server EKU - matches the NEPKI services profile
    assert cert.subject == x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CACTUS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "rg-1-Aggregator-1"),
        ]
    )
    assert cert.issuer == ica_cert.subject
    assert _san(cert).get_values_for_type(x509.DNSName) == [domain]
    assert _ext(cert, x509.SubjectAlternativeName).critical is False
    assert _policy_oids(cert) == [OID_DEV_GENERIC, OID_POLICY_COMMERCIAL]
    assert _ext(cert, x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
    )

    hmn = _hardware_module_name(cert)
    assert str(hmn["hwType"]) == "1.3.6.1.4.1.64.1.1.1"
    assert bytes(hmn["hwSerialNum"]) == b"cactus-rg-1-Aggregator-1"
