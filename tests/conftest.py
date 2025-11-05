import base64
import inspect
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import jwt
import pytest
from assertical.fixtures.environment import environment_snapshot
from assertical.fixtures.fastapi import start_app_with_client
from assertical.fixtures.postgres import generate_async_conn_str_from_connection
from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from kubernetes.client import V1Secret
from psycopg import Connection
from sqlalchemy import NullPool, create_engine

from cactus_orchestrator.auth import jwt_validator
from cactus_orchestrator.k8s.certificate.create import (
    calculate_rfc5280_subject_key_identifier_method_2,
    generate_client_p12_ec,
)
from cactus_orchestrator.model import Base
from cactus_orchestrator.settings import _reset_current_settings, get_current_settings


@pytest.fixture
def preserved_environment():
    with environment_snapshot():
        yield


@pytest.fixture(autouse=True)
def base_environment(preserved_environment, request):

    os.environ["IDLETEARDOWNTASK_ENABLE"] = "false"
    os.environ["JWTAUTH_ISSUER"] = "https://test-cactus-issuer.example.com"
    os.environ["TEST_EXECUTION_FQDN"] = "cactus-testing.test.fqdn"

    idleteardowntask_enable = request.node.get_closest_marker("idleteardowntask_enable")
    if idleteardowntask_enable:
        os.environ["IDLETEARDOWNTASK_ENABLE"] = "true"
        repeat_every_sec = idleteardowntask_enable.args[0]
        os.environ["IDLETEARDOWNTASK_REPEAT_EVERY_SECONDS"] = str(repeat_every_sec)


@pytest.fixture
def pg_empty_config(postgresql, preserved_environment) -> Generator[Connection, None, None]:
    """Sets up the testing DB, applies migrations but does NOT add any entities"""

    # Install the ORCHESTRATOR_DATABASE_URL before running migrations
    os.environ["ORCHESTRATOR_DATABASE_URL"] = generate_async_conn_str_from_connection(postgresql)

    sync_conn_string = (
        f"postgresql+psycopg://{postgresql.info.user}:@{postgresql.info.host}:{postgresql.info.port}"
        f"/{postgresql.info.dbname}"
    )
    engine = create_engine(sync_conn_string, echo=False, poolclass=NullPool)
    Base.metadata.create_all(engine)

    yield postgresql

    Base.metadata.drop_all(engine)


@pytest.fixture(scope="session")
def serca_cert_key_pair():
    # This isn't a fully compliant 2030.5 SERCA cert but is close enough for our tests
    serca_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SERCA")])
    ski = x509.SubjectKeyIdentifier(calculate_rfc5280_subject_key_identifier_method_2(serca_key.public_key()))

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(serca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .sign(serca_key, hashes.SHA256())  # Self signed
    )
    return (ca_cert, serca_key)


@pytest.fixture(scope="session")
def mca_cert_key_pair(serca_cert_key_pair):
    # This isn't a fully compliant 2030.5 MCA cert but is close enough for our tests
    serca_cert, serca_key = serca_cert_key_pair

    mca_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MCA")])

    ski = x509.SubjectKeyIdentifier(calculate_rfc5280_subject_key_identifier_method_2(mca_key.public_key()))
    issuer_ski = serca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(mca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(serca_key, hashes.SHA256())
    )
    return (ca_cert, mca_key)


@pytest.fixture(scope="session")
def mica_cert_key_pair(mca_cert_key_pair):
    # This isn't a fully compliant 2030.5 MICA cert but is close enough for our tests
    mca_cert, mca_key = mca_cert_key_pair

    mica_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MICA")])

    ski = x509.SubjectKeyIdentifier(calculate_rfc5280_subject_key_identifier_method_2(mica_key.public_key()))
    issuer_ski = mca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value)

    mica_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(mica_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(mca_key, hashes.SHA256())
    )
    return (mica_cert, mica_key)


@pytest.fixture(scope="session")
def rsa_key():
    return asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def ec_ca_cert_key_pair() -> tuple[x509.Certificate, asymmetric.ec.EllipticCurvePrivateKey]:
    # Generate EC private key using secp256r1 (aka prime256v1)
    ca_key = asymmetric.ec.generate_private_key(asymmetric.ec.SECP256R1())

    # CA subject
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "IEEE 2030.5 Root"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CACTUS"),
        ]
    )

    # Build self-signed certificate with ECDSA
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())  # ECDSA signature with SHA-256
    )

    return (ca_cert, ca_key)


@pytest.fixture(scope="session")
def ec_mica_cert_key_pair_from_file() -> tuple[x509.Certificate, asymmetric.ec.EllipticCurvePrivateKey]:
    """Get cert and key from files."""
    with open("tests/data/mica.crt", "rb") as cert_file:
        cert_data = cert_file.read()

    with open("tests/data/mica.key", "rb") as key_file:
        key_data = key_file.read()

    mica_cert = x509.load_pem_x509_certificate(cert_data, backends.default_backend())
    mica_key = serialization.load_pem_private_key(key_data, password=None, backend=backends.default_backend())
    assert isinstance(mica_key, asymmetric.ec.EllipticCurvePrivateKey)

    return (mica_cert, mica_key)


@pytest.fixture
def ec_cert_key_pair(request: pytest.FixtureRequest) -> tuple[x509.Certificate, asymmetric.ec.EllipticCurvePrivateKey]:
    """Indirect proxying of related fixtures for parametrization."""
    if request.param == "ec_ca_cert_key_pair":
        return request.getfixturevalue("ec_ca_cert_key_pair")
    elif request.param == "ec_mica_cert_key_pair_from_file":
        return request.getfixturevalue("ec_mica_cert_key_pair_from_file")
    else:
        raise ValueError(f"Unknown fixture name: {request.param}")


@pytest.fixture(scope="function")
def valid_user_p12_and_der(mca_cert_key_pair, mica_cert_key_pair) -> tuple[bytes, bytes]:
    mca_cert, mca_key = mca_cert_key_pair
    mica_cert, mica_key = mica_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12_ec(mica_key, mica_cert, mca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    return cl_p12, cl_der


@pytest.fixture(scope="function")
def expired_user_p12_and_der(mca_cert_key_pair, mica_cert_key_pair) -> tuple[bytes, bytes]:
    mca_cert, mca_key = mca_cert_key_pair
    mica_cert, mica_key = mica_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12_ec(
        mica_key,
        mica_cert,
        mca_cert,
        "test",
        "abc",
        not_before=datetime.now(timezone.utc) - timedelta(days=3),
        not_after=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    return cl_p12, cl_der


@pytest.fixture(scope="session")
def kid_and_jwks_stub(rsa_key) -> tuple[str, dict[str, list[str, Any]]]:
    public_key = rsa_key.public_key()
    kid = "test-kid"
    public_numbers = public_key.public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, "big")).decode("utf-8").rstrip("="),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, "big")).decode("utf-8").rstrip("="),
            }
        ]
    }
    return kid, jwks


@pytest.fixture(scope="session")
def mock_jwt_validator_jwks_cache(mica_cert_key_pair) -> dict[str, str]:
    # init for tests
    _, mica_key = mica_cert_key_pair

    public_key = mica_key.public_key()
    return {
        "test-kid": public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
    }


@pytest.fixture(scope="session")
def patch_jwks_request(kid_and_jwks_stub):
    _, jwks = kid_and_jwks_stub
    with patch("cactus_orchestrator.auth.httpx.AsyncClient") as mock_httpx_client_cls:
        mock_httpx_client_inst = AsyncMock()
        mock_httpx_client_cls.return_value.__aenter__.return_value = mock_httpx_client_inst
        mock_httpx_client_inst.get = AsyncMock(return_value=Mock())
        mock_httpx_client_inst.get.return_value.json.return_value = jwks
        yield


def valid_token_for_user(subject: str, ca_key, kid, scope, permissions) -> str:
    payload = {
        "sub": subject,
        "aud": os.environ["JWTAUTH_AUDIENCE"],
        "iss": os.environ["JWTAUTH_ISSUER"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
        "scope": scope,
        "permissions": permissions,
    }

    token = jwt.encode(
        payload,
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        algorithm="RS256",
        headers={"kid": kid},
    )

    return token


@pytest.fixture(scope="function")
def valid_jwt_user1(mock_jwt_validator_jwks_cache, rsa_key) -> str:
    kid = list(mock_jwt_validator_jwks_cache.keys())[0]
    return valid_token_for_user("user1", rsa_key, kid, "user:all", ["user:all"])


@pytest.fixture(scope="function")
def valid_jwt_user2(mock_jwt_validator_jwks_cache, rsa_key) -> str:
    kid = list(mock_jwt_validator_jwks_cache.keys())[0]
    return valid_token_for_user("user2", rsa_key, kid, "user:all", ["user:all"])


@pytest.fixture(scope="function")
def valid_jwt_user3(mock_jwt_validator_jwks_cache, rsa_key) -> str:
    kid = list(mock_jwt_validator_jwks_cache.keys())[0]
    return valid_token_for_user("user3", rsa_key, kid, "user:all", ["user:all"])


@pytest.fixture(scope="function")
def valid_jwt_no_user(mock_jwt_validator_jwks_cache, rsa_key) -> str:
    kid = list(mock_jwt_validator_jwks_cache.keys())[0]
    return valid_token_for_user("user-dne", rsa_key, kid, "user:all", ["user:all"])


@pytest.fixture(scope="function")
def valid_jwt_admin1(mock_jwt_validator_jwks_cache, rsa_key) -> str:
    kid = list(mock_jwt_validator_jwks_cache.keys())[0]
    return valid_token_for_user("admin-user", rsa_key, kid, "user:all", ["admin:all", "user:all"])


@pytest.fixture
def mock_k8s_tls_secret(mica_cert_key_pair):
    cert_pem, cert_key = mica_cert_key_pair
    secret_mock = MagicMock(spec=V1Secret)
    secret_mock.data = {
        "tls.crt": base64.b64encode(
            cert_pem.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
        ).decode(),
        "tls.key": base64.b64encode(
            cert_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode(),
    }
    return secret_mock


@pytest.fixture
def generate_k8s_class_instance():
    def func(t: type, **kwargs):
        def get_init_params(t):
            for i in inspect.signature(t.__init__).parameters.keys():
                if i != "self":
                    yield i

        members = {k: MagicMock() for k in get_init_params(t)} | kwargs
        return t(**members)

    return func


def execute_test_sql_file(cfg: Connection, path_to_sql_file: str) -> None:
    with open(path_to_sql_file) as f:
        sql = f.read()
    with cfg.cursor() as cursor:
        cursor.execute(sql)
        cfg.commit()


@pytest.fixture
def pg_base_config(pg_empty_config):
    """Adds a very minimal config to the database from base_config.sql"""
    execute_test_sql_file(pg_empty_config, "tests/data/base_config.sql")

    yield pg_empty_config


@pytest.fixture
async def client(pg_empty_config, patch_jwks_request):
    from cactus_orchestrator.main import generate_app

    # This is a sideeffect of some nasty globals that should be unpicked in the future
    jwt_validator._reload_settings()
    _reset_current_settings()

    async with start_app_with_client(generate_app(get_current_settings())) as c:
        yield c
