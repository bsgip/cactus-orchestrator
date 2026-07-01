import base64
import os
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import jwt
import pytest
from assertical.fake.generator import generate_class_instance
from assertical.fixtures.environment import environment_snapshot
from assertical.fixtures.fastapi import start_app_with_client
from assertical.fixtures.postgres import generate_async_conn_str_from_connection
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from envoy.server.alembic import upgrade as envoy_upgrade
from psycopg import Connection
from sqlalchemy import NullPool, create_engine

from cactus_orchestrator.auth import jwt_validator
from cactus_orchestrator.certificate.create import (
    calculate_rfc5280_subject_key_identifier_method_2,
    generate_aggregator_certificate,
    generate_device_certificate,
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
    os.environ["CACTUS_FQDN"] = "cactus-testing.test.fqdn"

    # Install images
    os.environ["CACTUS_IMAGE__V12__CSIP_AUS_VERSION"] = "v1.2"
    os.environ["CACTUS_IMAGE__V12__POSTGRES"] = "postgres:12"
    os.environ["CACTUS_IMAGE__V12__INIT"] = "init:12"
    os.environ["CACTUS_IMAGE__V12__ENVOY"] = "envoy:12"
    os.environ["CACTUS_IMAGE__V12__RUNNER"] = "runner:12"

    os.environ["CACTUS_IMAGE__V13__CSIP_AUS_VERSION"] = "v1.3"
    os.environ["CACTUS_IMAGE__V13__POSTGRES"] = "postgres:13"
    os.environ["CACTUS_IMAGE__V13__INIT"] = "init:13"
    os.environ["CACTUS_IMAGE__V13__ENVOY"] = "envoy:13"
    os.environ["CACTUS_IMAGE__V13__RUNNER"] = "runner:13"

    os.environ["CACTUS_IMAGE__V13BETA__CSIP_AUS_VERSION"] = "v1.3-beta/storage"
    os.environ["CACTUS_IMAGE__V13BETA__POSTGRES"] = "postgres:13-beta"
    os.environ["CACTUS_IMAGE__V13BETA__INIT"] = "init:13-beta"
    os.environ["CACTUS_IMAGE__V13BETA__ENVOY"] = "envoy:13-beta"
    os.environ["CACTUS_IMAGE__V13BETA__RUNNER"] = "runner:13-beta"

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


# keyUsage asserted on every CA certificate, matching the NEPKI CA profile (cactus-deploy pki/create-cert.sh)
_CA_KEY_USAGE = x509.KeyUsage(
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


def _build_ca_cert(
    common_name: str,
    subject_key: ec.EllipticCurvePrivateKey,
    path_length: int | None,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
) -> x509.Certificate:
    """Builds a CA certificate mirroring the structural NEPKI CA profile (cactus-deploy pki/create-cert.sh): a
    C=AU,O=CACTUS,CN=<common_name> subject, critical CA basicConstraints with the supplied pathlen, keyCertSign+cRLSign
    keyUsage and a method-2 subjectKeyIdentifier. issuer=None yields a self-signed root (SERCA); otherwise the cert is
    signed by the issuer and carries the matching authorityKeyIdentifier."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CACTUS"),
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
        .add_extension(_CA_KEY_USAGE, critical=True)
        .add_extension(ski, critical=False)
    )
    if issuer_cert is not None:
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value), critical=False
        )

    return builder.sign(signing_key, hashes.SHA256())


@pytest.fixture(scope="session")
def serca_cert_key_pair() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Shared self-signed root trust anchor (SERCA)."""
    serca_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    return (_build_ca_cert("IEEE 2030.5 Root", serca_key, path_length=None), serca_key)


@pytest.fixture(scope="session")
def mca_cert_key_pair(serca_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Device chain level-2 CA (MCA), signed by SERCA."""
    mca_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    return (_build_ca_cert("IEEE 2030.5 MCA", mca_key, path_length=1, issuer=serca_cert_key_pair), mca_key)


@pytest.fixture(scope="session")
def mica_cert_key_pair(mca_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Device chain level-3 CA (MICA), signs device EE certs."""
    mica_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    return (_build_ca_cert("IEEE 2030.5 MICA", mica_key, path_length=0, issuer=mca_cert_key_pair), mica_key)


@pytest.fixture(scope="session")
def services_pca_cert_key_pair(serca_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Shared Services PCA, signed by SERCA - the common parent of the Aggregator and DNSP ICAs."""
    pca_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    return (_build_ca_cert("CACTUS Services PCA", pca_key, path_length=1, issuer=serca_cert_key_pair), pca_key)


@pytest.fixture(scope="session")
def agg_ica_cert_key_pair(services_pca_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Aggregator chain level-3 CA, signs aggregator EE certs."""
    ica_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    return (_build_ca_cert("CACTUS Aggregator ICA", ica_key, path_length=0, issuer=services_pca_cert_key_pair), ica_key)


@pytest.fixture(scope="session")
def dnsp_ica_cert_key_pair(services_pca_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Utility-server (DNSP) chain level-3 CA, signs the envoy EE cert."""
    ica_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    return (_build_ca_cert("CACTUS DNSP ICA", ica_key, path_length=0, issuer=services_pca_cert_key_pair), ica_key)


@pytest.fixture(scope="session")
def envoy_ee_cert_key_pair(dnsp_ica_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Utility-server (envoy) EE cert with a wildcard SAN, signed by the DNSP ICA. Uses the services EE profile."""
    ica_cert, ica_key = dnsp_ica_cert_key_pair
    envoy_key, envoy_cert = generate_aggregator_certificate(ica_key, ica_cert, 0, "envoy", "*.cactus-testing.test.fqdn")
    return (envoy_cert, envoy_key)


@pytest.fixture(scope="session")
def client_cert_key_pair(mica_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    # This isn't a fully compliant 2030.5 client cert but is close enough for our tests
    mica_cert, mica_key = mica_cert_key_pair

    client_key, client_cert = generate_device_certificate(mica_key, mica_cert, 123, "ID 123")
    return (client_cert, client_key)


@pytest.fixture(scope="session")
def client_cert_pem_bytes(client_cert_key_pair) -> bytes:
    return client_cert_key_pair[0].public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def client_cert_key_pair_expired(mica_cert_key_pair) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    # This isn't a fully compliant 2030.5 client cert but is close enough for our tests
    mica_cert, mica_key = mica_cert_key_pair

    client_key, client_cert = generate_device_certificate(
        mica_key,
        mica_cert,
        456,
        "Expired ID 456",
        datetime.now(UTC) - timedelta(days=100),
        datetime.now(UTC),
    )
    return (client_cert, client_key)


@pytest.fixture(scope="session")
def client_cert_expired_pem_bytes(client_cert_key_pair_expired) -> bytes:
    return client_cert_key_pair_expired[0].public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def kid_and_jwks_stub(rsa_key) -> tuple[str, dict[str, list[dict[str, str]]]]:
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
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
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


def execute_test_sql_file(cfg: Connection, path_to_sql_file: str) -> None:
    with open(path_to_sql_file) as f:
        sql = f.read()
    with cfg.cursor() as cursor:
        cursor.execute(sql)  # ty:ignore[no-matching-overload]
        cfg.commit()


@pytest.fixture
def pg_base_config(pg_empty_config):
    """Adds a very minimal config to the database from base_config.sql"""
    execute_test_sql_file(pg_empty_config, "tests/data/base_config.sql")

    yield pg_empty_config


@pytest.fixture
def pg_envoy_base_config(postgresql, preserved_environment) -> Generator[Connection, None, None]:
    """Sets up a temporary envoy DB with migrations and minimal seed data for power_limit_chart tests."""
    os.environ["DATABASE_URL"] = generate_async_conn_str_from_connection(postgresql)
    envoy_upgrade()
    execute_test_sql_file(postgresql, "tests/data/envoy_base_config.sql")
    yield postgresql


@pytest.fixture
def pg_compliance_config(pg_empty_config):
    """Adds enough records to support compliance checking"""
    execute_test_sql_file(pg_empty_config, "tests/data/compliance_config.sql")

    yield pg_empty_config


@pytest.fixture
async def client(pg_empty_config, patch_jwks_request):
    from cactus_orchestrator.main import generate_app

    # This is a sideeffect of some nasty globals that should be unpicked in the future
    jwt_validator._reload_settings()
    _reset_current_settings()

    async with start_app_with_client(generate_app(get_current_settings())) as c:
        yield c


@pytest.fixture
def reporting_data_version():
    return 1


@pytest.fixture
def reporting_data_json(reporting_data_version):

    from cactus_runner.models import ActiveTestProcedure, CheckResult, ReportingData, ResourceAnnotations, RunnerState
    from cactus_test_definitions.client import TestProcedureId, get_test_procedure

    runner_state = generate_class_instance(
        RunnerState,
        active_test_procedure=generate_class_instance(
            ActiveTestProcedure,
            definition=get_test_procedure(test_procedure_id=TestProcedureId.ALL_01),
            step_status={},
            finished_zip_path=None,
            resource_annotations=ResourceAnnotations(der_control_ids_by_alias={"a": 1}),
        ),
    )
    reporting_data = generate_class_instance(
        ReportingData.v(reporting_data_version),
        check_results={"key": generate_class_instance(CheckResult)},
        runner_state=runner_state,
    )
    reporting_data_json = reporting_data.to_json()
    return reporting_data_json


@pytest.fixture
def file_data():
    import io
    import zipfile

    PDF_FILENAME = "CactusTestProcedureReport.pdf"
    TXT_FILENAME = "other_file.txt"
    PDF_DATA = b"before"
    TXT_DATA = b"other"

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        with archive.open(PDF_FILENAME, "w") as file:
            file.write(PDF_DATA)
        with archive.open(TXT_FILENAME, "w") as file:
            file.write(TXT_DATA)

    zip_data = zip_buffer.getvalue()
    return zip_data


@pytest.fixture
def pg_regeneration_config(pg_base_config, reporting_data_json, reporting_data_version, file_data):
    """Adds zip file data and working reporting data to run artifact id 3 (run 5)"""
    stmt = """UPDATE run_artifact SET reporting_data = %s, version = %s, file_data = %s WHERE id = 3;"""
    with pg_base_config.cursor() as cursor:
        cursor.execute(stmt, (reporting_data_json, reporting_data_version, file_data))
        pg_base_config.commit()
    yield pg_base_config


@pytest.fixture
def add_ignored_v12_version(client):

    os.environ["IGNORED_CSIP_AUS_VERSIONS"] = '["v1.2"]'

    # This is a sideeffect of some nasty globals that should be unpicked in the future
    _reset_current_settings()
