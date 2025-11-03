from dataclasses import dataclass
from http import HTTPStatus
from itertools import product
from typing import Generator
from unittest.mock import Mock, patch

import pytest
from assertical.fixtures.postgres import generate_async_session
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy import select
from sqlalchemy.orm import undefer

from cactus_orchestrator.api.certificate import CertificateRouteType
from cactus_orchestrator.model import User


@dataclass
class MockedK8s:
    generate_client_p12_ec: Mock
    fetch_certificate_key_pair: Mock
    fetch_certificate_only: Mock
    pkcs12: Mock


@pytest.fixture
def k8s_mock() -> Generator[MockedK8s, None, None]:
    with (
        patch("cactus_orchestrator.api.certificate.generate_client_p12_ec") as generate_client_p12_ec,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_key_pair") as fetch_certificate_key_pair,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_only") as fetch_certificate_only,
        patch("cactus_orchestrator.api.certificate.pkcs12") as pkcs12,
    ):
        yield MockedK8s(
            generate_client_p12_ec=generate_client_p12_ec,
            fetch_certificate_key_pair=fetch_certificate_key_pair,
            fetch_certificate_only=fetch_certificate_only,
            pkcs12=pkcs12,
        )


@dataclass
class MockedK8sSecretsOnly:
    fetch_certificate_key_pair: Mock
    fetch_certificate_only: Mock


@pytest.fixture
def k8s_mock_secrets_only() -> Generator[MockedK8sSecretsOnly, None, None]:
    with (
        patch("cactus_orchestrator.api.certificate.fetch_certificate_key_pair") as fetch_certificate_key_pair,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_only") as fetch_certificate_only,
    ):
        yield MockedK8sSecretsOnly(
            fetch_certificate_key_pair=fetch_certificate_key_pair,
            fetch_certificate_only=fetch_certificate_only,
        )


@pytest.mark.parametrize("cert_type", CertificateRouteType)
@pytest.mark.asyncio
async def test_fetch_existing_certificate_no_user(client, valid_jwt_no_user, cert_type: CertificateRouteType):
    # Arrange

    # Act
    res = await client.get(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_jwt_no_user}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize("cert_type", CertificateRouteType)
async def test_fetch_existing_certificate(client, pg_base_config, valid_jwt_user1, cert_type: CertificateRouteType):

    # Arrange
    device_cert_data = b"device cert data"
    agg_cert_data = b"agg cert data"
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.aggregator_certificate_p12_bundle = agg_cert_data
        user.device_certificate_p12_bundle = device_cert_data
        await session.commit()

    # Act
    res = await client.get(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.headers["content-type"] == "application/x-pkcs12"
    if cert_type == CertificateRouteType.aggregator:
        assert res.content == agg_cert_data
    else:
        assert res.content == device_cert_data


@pytest.mark.asyncio
async def test_fetch_existing_certificate_bad_cert_type(valid_jwt_user1, client, pg_base_config):
    res = await client.get("/certificate/agg_not_a_real_cert", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert res.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize("cert_type", CertificateRouteType)
async def test_create_new_certificate_full_creation(
    client,
    pg_base_config,
    valid_jwt_user1,
    k8s_mock_secrets_only: MockedK8sSecretsOnly,
    mca_cert_key_pair,
    mica_cert_key_pair,
    cert_type: CertificateRouteType,
):
    """Test creating a new certificate for a user"""

    # Arrange
    # Strip out any user certs
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.aggregator_certificate_p12_bundle = None
        user.aggregator_certificate_x509_der = None
        user.aggregator_certificate_pem = None
        user.aggregator_certificate_pem_key = None
        user.device_certificate_p12_bundle = None
        user.device_certificate_x509_der = None
        user.device_certificate_pem = None
        user.device_certificate_pem_key = None
        await session.commit()

    # The only part we mock is the fetching of certs from the k8's secret store
    async def mocked_fetch_certificate_key_pair(secret_name, namespace=None, passphrase_secret=None):
        if secret_name == "tls-mica-cactus":
            return mica_cert_key_pair
        else:
            raise Exception(f"Mock error - unexpected secret_name '{secret_name}'")

    async def mocked_fetch_certificate_only(secret_name, namespace=None):
        if secret_name == "cert-mca-cactus":
            return mca_cert_key_pair[0]
        else:
            raise Exception(f"Mock error - unexpected secret_name '{secret_name}'")

    k8s_mock_secrets_only.fetch_certificate_key_pair.side_effect = mocked_fetch_certificate_key_pair
    k8s_mock_secrets_only.fetch_certificate_only.side_effect = mocked_fetch_certificate_only

    # Act
    res = await client.put(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content and len(res.content)
    assert res.headers["content-type"] == "application/x-pkcs12"
    assert res.headers["X-Certificate-Password"]

    k8s_mock_secrets_only.fetch_certificate_key_pair.assert_called_once()
    k8s_mock_secrets_only.fetch_certificate_only.assert_called_once()

    # Certificate should be signed by MICA/MCA cert (but not SERCA)
    client_key, client_cert, additional_certs = pkcs12.load_key_and_certificates(
        res.content, res.headers["X-Certificate-Password"].encode()
    )
    assert client_key
    assert client_cert
    assert additional_certs and len(additional_certs) == 2, "Should be signed by (and include) MICA/MCA"
    assert additional_certs[0] == mica_cert_key_pair[0]
    assert additional_certs[1] == mca_cert_key_pair[0]

    # Validate database got stored data
    async with generate_async_session(pg_base_config) as session:
        user = (
            await session.execute(
                select(User)
                .where(User.user_id == 1)
                .options(
                    undefer(User.aggregator_certificate_p12_bundle),
                    undefer(User.aggregator_certificate_x509_der),
                    undefer(User.aggregator_certificate_pem),
                    undefer(User.aggregator_certificate_pem_key),
                    undefer(User.device_certificate_p12_bundle),
                    undefer(User.device_certificate_x509_der),
                    undefer(User.device_certificate_pem),
                    undefer(User.device_certificate_pem_key),
                )
            )
        ).scalar_one()

        if cert_type == CertificateRouteType.aggregator:
            assert user.aggregator_certificate_p12_bundle
            assert user.aggregator_certificate_x509_der
            assert user.aggregator_certificate_pem
            assert user.aggregator_certificate_pem_key
            assert user.device_certificate_p12_bundle is None
            assert user.device_certificate_x509_der is None
            assert user.device_certificate_pem is None
            assert user.device_certificate_pem_key is None
        else:
            assert user.aggregator_certificate_p12_bundle is None
            assert user.aggregator_certificate_x509_der is None
            assert user.aggregator_certificate_pem is None
            assert user.aggregator_certificate_pem_key is None
            assert user.device_certificate_p12_bundle
            assert user.device_certificate_x509_der
            assert user.device_certificate_pem
            assert user.device_certificate_pem_key


@pytest.mark.parametrize("cert_type, existing_bytes", product(CertificateRouteType, [bytes([0, 1, 99]), None]))
async def test_create_new_certificate_existing_user(
    client, pg_base_config, valid_jwt_user1, k8s_mock: MockedK8s, cert_type, existing_bytes
):
    """Test creating a new certificate for a user"""

    # Arrange
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.aggregator_certificate_p12_bundle = existing_bytes
        user.aggregator_certificate_x509_der = existing_bytes
        user.aggregator_certificate_pem = existing_bytes
        user.aggregator_certificate_pem_key = existing_bytes
        user.device_certificate_p12_bundle = existing_bytes
        user.device_certificate_x509_der = existing_bytes
        user.device_certificate_pem = existing_bytes
        user.device_certificate_pem_key = existing_bytes
        await session.commit()

    mock_ca_key = b"mock_ca_key_data"
    mock_ca_cert = b"mock_ca_cert_data"
    k8s_mock.fetch_certificate_key_pair.return_value = (mock_ca_cert, mock_ca_key)

    mock_client_p12 = b"mock_client_p12_data"
    mock_client_cert_bytes = b"mock_client_cert_data"
    mock_client_pem_cert_bytes = b"mock_client_pem_cert"
    mock_client_pem_key_bytes = b"mock_client_pem_key"
    mock_client_pem_cert = Mock()
    mock_client_pem_cert.public_bytes.return_value = mock_client_pem_cert_bytes
    mock_client_pem_key = Mock()
    mock_client_pem_key.private_bytes.return_value = mock_client_pem_key_bytes
    mock_client_cert = Mock()
    mock_client_cert.public_bytes = Mock(return_value=mock_client_cert_bytes)
    k8s_mock.generate_client_p12_ec.return_value = (mock_client_p12, mock_client_cert)
    k8s_mock.pkcs12.load_key_and_certificates.return_value = (mock_client_pem_key, mock_client_pem_cert, "dunder")

    # Act
    res = await client.put(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content == mock_client_p12
    assert res.headers["content-type"] == "application/x-pkcs12"
    assert res.headers["X-Certificate-Password"]

    k8s_mock.fetch_certificate_key_pair.assert_called_once()
    k8s_mock.generate_client_p12_ec.assert_called_once()
    k8s_mock.pkcs12.load_key_and_certificates.assert_called_once()

    async with generate_async_session(pg_base_config) as session:
        user = (
            await session.execute(
                select(User)
                .where(User.user_id == 1)
                .options(
                    undefer(User.aggregator_certificate_p12_bundle),
                    undefer(User.aggregator_certificate_x509_der),
                    undefer(User.aggregator_certificate_pem),
                    undefer(User.aggregator_certificate_pem_key),
                    undefer(User.device_certificate_p12_bundle),
                    undefer(User.device_certificate_x509_der),
                    undefer(User.device_certificate_pem),
                    undefer(User.device_certificate_pem_key),
                )
            )
        ).scalar_one()

        if cert_type == CertificateRouteType.aggregator:
            assert user.aggregator_certificate_p12_bundle == mock_client_p12
            assert user.aggregator_certificate_x509_der == mock_client_cert_bytes
            assert user.aggregator_certificate_pem == mock_client_pem_cert_bytes
            assert user.aggregator_certificate_pem_key == mock_client_pem_key_bytes
            assert user.device_certificate_p12_bundle == existing_bytes
            assert user.device_certificate_x509_der == existing_bytes
            assert user.device_certificate_pem == existing_bytes
            assert user.device_certificate_pem_key == existing_bytes
        else:
            assert user.aggregator_certificate_p12_bundle == existing_bytes
            assert user.aggregator_certificate_x509_der == existing_bytes
            assert user.aggregator_certificate_pem == existing_bytes
            assert user.aggregator_certificate_pem_key == existing_bytes
            assert user.device_certificate_p12_bundle == mock_client_p12
            assert user.device_certificate_x509_der == mock_client_cert_bytes
            assert user.device_certificate_pem == mock_client_pem_cert_bytes
            assert user.device_certificate_pem_key == mock_client_pem_key_bytes


@pytest.mark.asyncio
async def test_create_new_certificate_bad_cert_type(client, valid_jwt_user1, k8s_mock: MockedK8s):
    """Test that regenerating a cert that DNE results in a failure"""
    # Arrange

    # Act
    res = await client.put("/certificate/agg_dne_cert", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND

    k8s_mock.fetch_certificate_key_pair.assert_not_called()
    k8s_mock.generate_client_p12_ec.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_current_certificate_authority_der(
    client, valid_jwt_user1, k8s_mock_secrets_only: MockedK8sSecretsOnly, serca_cert_key_pair
):
    """Basic success path test."""

    # Arrange
    k8s_mock_secrets_only.fetch_certificate_only.return_value = serca_cert_key_pair[0]

    # Act
    response_1 = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response_1.status_code == HTTPStatus.OK
    assert response_1.headers["content-type"] == "application/x-x509-ca-cert"
    assert x509.load_der_x509_certificate(response_1.content, default_backend()) == serca_cert_key_pair[0]

    response_2 = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response_2.status_code == HTTPStatus.OK
    assert response_2.headers["content-type"] == "application/x-x509-ca-cert"
    assert x509.load_der_x509_certificate(response_2.content, default_backend()) == serca_cert_key_pair[0]

    # Assert
    k8s_mock_secrets_only.fetch_certificate_only.call_count == 2
