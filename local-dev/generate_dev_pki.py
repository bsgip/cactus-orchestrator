"""Generates the throwaway local-dev PKI the orchestrator needs at startup - see README.md §3.

Writes only the files referenced by the CERT_* vars in sample.env, in the same directory layout as the
production tooling (cactus-deploy pki/create-cert.sh + stage-certs.sh) so the two stay recognisable:

    pki/serca/serca.cert.pem
    pki/device-chain/MCA.cert.pem  MICA.cert.pem  MICA.key.pem
    pki/aggregator-chain/pca.cert.pem  ica.cert.pem  ica.key.pem
    pki/envoy/envoy.fullchain.pem  envoy.key.pem

Usage (from the repo root):  uv run python local-dev/generate_dev_pki.py [--fqdn cactus.local.test]
"""

import argparse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cactus_orchestrator.certificate.chains import build_ca_cert
from cactus_orchestrator.certificate.create import generate_aggregator_certificate

type CertKeyPair = tuple[x509.Certificate, ec.EllipticCurvePrivateKey]


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fqdn", default="cactus.local.test", help="must match CACTUS_FQDN in orchestrator.env")
    parser.add_argument("--out", default=Path(__file__).parent / "pki", type=Path, help="output directory")
    args = parser.parse_args()
    out: Path = args.out

    if (out / "serca" / "serca.cert.pem").exists():
        raise SystemExit(f"{out} already contains a PKI - delete it first to regenerate")

    def new_ca(common_name: str, path_length: int | None, issuer: CertKeyPair | None = None) -> CertKeyPair:
        key = ec.generate_private_key(ec.SECP256R1())
        return (build_ca_cert(common_name, key, path_length=path_length, issuer=issuer), key)

    serca = new_ca("IEEE 2030.5 Root", path_length=None)
    mca = new_ca("IEEE 2030.5 MCA", path_length=1, issuer=serca)
    mica = new_ca("IEEE 2030.5 MICA", path_length=0, issuer=mca)
    pca = new_ca("CACTUS Services PCA", path_length=1, issuer=serca)
    agg_ica = new_ca("CACTUS Aggregator ICA", path_length=0, issuer=pca)
    dnsp_ica = new_ca("CACTUS DNSP ICA", path_length=0, issuer=pca)

    # Static wildcard envoy EE (the utility-server identity envoy presents on outbound notifications).
    # Uses the services EE profile - same as the production dnsp chain.
    envoy_key, envoy_cert = generate_aggregator_certificate(dnsp_ica[1], dnsp_ica[0], 0, "envoy", f"*.{args.fqdn}")

    files: dict[str, bytes] = {
        "serca/serca.cert.pem": _pem(serca[0]),
        "device-chain/MCA.cert.pem": _pem(mca[0]),
        "device-chain/MICA.cert.pem": _pem(mica[0]),
        "device-chain/MICA.key.pem": _key_pem(mica[1]),
        "aggregator-chain/pca.cert.pem": _pem(pca[0]),
        "aggregator-chain/ica.cert.pem": _pem(agg_ica[0]),
        "aggregator-chain/ica.key.pem": _key_pem(agg_ica[1]),
        "envoy/envoy.fullchain.pem": _pem(envoy_cert) + _pem(dnsp_ica[0]) + _pem(pca[0]),
        "envoy/envoy.key.pem": _key_pem(envoy_key),
    }
    for rel, content in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o600 if rel.endswith("key.pem") else 0o644)
        print(f"wrote {path}")

    print(f"\nDone - SAN *.{args.fqdn}. Point the CERT_* vars in orchestrator.env at {out.resolve()}/")


if __name__ == "__main__":
    main()
