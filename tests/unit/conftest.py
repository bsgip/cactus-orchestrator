import base64
import inspect
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from cryptography.x509.oid import NameOID
from jose import jwt
from kubernetes.client import V1Secret
from sqlalchemy import Connection, NullPool, create_engine

from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.model import Base


# pytest startup / shutdown configs
def pytest_configure():
    """Monkey patch load_k8s_config at pytest startup (before discovery)."""
    patcher = patch("cactus_orchestrator.settings.load_k8s_config", return_value=None)
    patcher.start()  # Start the patch immediately
    pytest._load_k8s_config_patcher = patcher  # Store it so we can stop it later


def pytest_unconfigure():
    pytest._load_k8s_config_patcher.stop()


@pytest.fixture(scope="session")
def ca_cert_key_pair():
    ca_key = asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return (ca_cert, ca_key)


@pytest.fixture(scope="function")
def valid_user_p12_and_der(ca_cert_key_pair) -> tuple[bytes, bytes]:
    ca_cert, ca_key = ca_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    return cl_p12, cl_der


@pytest.fixture(scope="session")
def kid_and_jwks_stub(ca_cert_key_pair) -> tuple[str, dict[str, list[str, Any]]]:
    # init for tests
    _, ca_key = ca_cert_key_pair

    public_key = ca_key.public_key()
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
def mock_jwt_validator_jwks_cache(ca_cert_key_pair) -> dict[str, str]:
    # init for tests
    _, ca_key = ca_cert_key_pair

    public_key = ca_key.public_key()
    return {
        "test-kid": public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
    }


@pytest.fixture(scope="session", autouse=True)
def patch_jwks_request(kid_and_jwks_stub):
    _, jwks = kid_and_jwks_stub
    with patch("cactus_orchestrator.auth.httpx.AsyncClient") as mock_httpx_client_cls:
        mock_httpx_client_inst = AsyncMock()
        mock_httpx_client_cls.return_value.__aenter__.return_value = mock_httpx_client_inst
        mock_httpx_client_inst.get = AsyncMock(return_value=Mock())
        mock_httpx_client_inst.get.return_value.json.return_value = jwks
        yield


@pytest.fixture(scope="function")
def valid_user_jwt(mock_jwt_validator_jwks_cache, ca_cert_key_pair) -> str:
    _, ca_key = ca_cert_key_pair
    kid = list(mock_jwt_validator_jwks_cache.keys())[0]

    payload = {
        "sub": "test-user",
        "aud": os.environ["JWTAUTH_AUDIENCE"],
        "iss": os.environ["JWTAUTH_ISSUER"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
        "scopes": "user:all",
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


@pytest.fixture
def mock_k8s_tls_secret(ca_cert_key_pair):
    cert_pem, cert_key = ca_cert_key_pair
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


@pytest.fixture
def pg_empty_conn(postgresql) -> Generator[Connection, None, None]:
    """Session for SQLAlchemy."""
    connection = (
        f"postgresql+psycopg://{postgresql.info.user}:@{postgresql.info.host}:{postgresql.info.port}"
        f"/{postgresql.info.dbname}"
    )
    engine = create_engine(connection, echo=False, poolclass=NullPool)

    Base.metadata.create_all(engine)

    with engine.connect() as conn:
        yield conn

    Base.metadata.drop_all(engine)
