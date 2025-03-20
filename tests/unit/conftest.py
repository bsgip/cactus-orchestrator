import os
import pytest
import inspect
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import base64
from typing import Generator

from jose import jwt
from kubernetes.client import V1Secret
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes, asymmetric
from cryptography.x509.oid import NameOID
from sqlalchemy import Connection, NullPool, create_engine


from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.model import Base
from cactus_orchestrator.auth import jwt_validator


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
def patch_jwk_cache(request, mock_jwt_validator_jwks_cache):
    if request.node.get_closest_marker("patch_jwk_cache"):
        with patch.object(
            jwt_validator._rsa_jwk_cache, "get_value", return_value=list(mock_jwt_validator_jwks_cache.values()[0])
        ):
            yield
    else:
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
