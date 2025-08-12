from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from itertools import product
from typing import Generator
from unittest.mock import Mock, patch

import pytest
from assertical.fixtures.postgres import generate_async_session
from sqlalchemy import select
from sqlalchemy.orm import undefer

from cactus_orchestrator.api.certificate import CertificateRouteType
from cactus_orchestrator.model import User


@dataclass
class MockedK8s:
    generate_client_p12: Mock
    fetch_certificate_key_pair: Mock
    fetch_certificate_only: Mock


@pytest.fixture
def k8s_mock() -> Generator[MockedK8s, None, None]:
    with (
        patch("cactus_orchestrator.api.certificate.generate_client_p12") as generate_client_p12,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_key_pair") as fetch_certificate_key_pair,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_only") as fetch_certificate_only,
    ):
        yield MockedK8s(
            generate_client_p12=generate_client_p12,
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
        user.device_certificate_p12_bundle = existing_bytes
        user.device_certificate_x509_der = existing_bytes
        await session.commit()

    mock_ca_key = b"mock_ca_key_data"
    mock_ca_cert = b"mock_ca_cert_data"
    k8s_mock.fetch_certificate_key_pair.return_value = (mock_ca_cert, mock_ca_key)

    mock_client_p12 = b"mock_client_p12_data"
    mock_client_cert_bytes = b"mock_client_cert_data"
    mock_client_cert = Mock()
    mock_client_cert.public_bytes = Mock(return_value=mock_client_cert_bytes)
    k8s_mock.generate_client_p12.return_value = (mock_client_p12, mock_client_cert)

    # Act
    res = await client.put(f"/certificate/{cert_type.value}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content == mock_client_p12
    assert res.headers["content-type"] == "application/x-pkcs12"
    assert res.headers["X-Certificate-Password"]

    k8s_mock.fetch_certificate_key_pair.assert_called_once()
    k8s_mock.generate_client_p12.assert_called_once()

    async with generate_async_session(pg_base_config) as session:
        user = (
            await session.execute(
                select(User)
                .where(User.user_id == 1)
                .options(
                    undefer(User.aggregator_certificate_p12_bundle),
                    undefer(User.aggregator_certificate_x509_der),
                    undefer(User.device_certificate_p12_bundle),
                    undefer(User.device_certificate_x509_der),
                )
            )
        ).scalar_one()

        if cert_type == CertificateRouteType.aggregator:
            assert user.aggregator_certificate_p12_bundle == mock_client_p12
            assert user.aggregator_certificate_x509_der == mock_client_cert_bytes
            assert user.device_certificate_p12_bundle == existing_bytes
            assert user.device_certificate_x509_der == existing_bytes
        else:
            assert user.aggregator_certificate_p12_bundle == existing_bytes
            assert user.aggregator_certificate_x509_der == existing_bytes
            assert user.device_certificate_p12_bundle == mock_client_p12
            assert user.device_certificate_x509_der == mock_client_cert_bytes


@pytest.mark.asyncio
async def test_create_new_certificate_bad_cert_type(client, valid_jwt_user1, k8s_mock: MockedK8s):
    """Test that regenerating a cert that DNE results in a failure"""
    # Arrange

    # Act
    res = await client.put("/certificate/agg_dne_cert", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.NOT_FOUND

    k8s_mock.fetch_certificate_key_pair.assert_not_called()
    k8s_mock.generate_client_p12.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_current_certificate_authority_der(client, valid_jwt_user1, k8s_mock: MockedK8s):
    """Basic success path test."""

    # Arrange
    x509_bytes = bytes([66, 44, 1])
    mock_cert = Mock()
    mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_cert.public_bytes = Mock(return_value=x509_bytes)
    k8s_mock.fetch_certificate_only.return_value = mock_cert

    # Act
    response_1 = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response_1.status_code == HTTPStatus.OK
    assert response_1.headers["content-type"] == "application/x-x509-ca-cert"
    assert response_1.content == x509_bytes

    response_2 = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response_2.status_code == HTTPStatus.OK
    assert response_2.headers["content-type"] == "application/x-x509-ca-cert"
    assert response_2.content == x509_bytes

    # Assert
    k8s_mock.fetch_certificate_only.assert_called_once()  # Should only be a single call - we're expecting a cache
