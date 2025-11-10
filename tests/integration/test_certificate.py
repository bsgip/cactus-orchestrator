import io
import zipfile
from dataclasses import dataclass
from http import HTTPStatus
from itertools import product
from typing import Generator
from unittest.mock import Mock, patch

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fixtures.postgres import generate_async_session
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, pkcs12
from sqlalchemy import select
from sqlalchemy.orm import undefer

from cactus_orchestrator.api.certificate import MEDIA_TYPE_PEM_CRT
from cactus_orchestrator.model import RunGroup, User
from cactus_orchestrator.schema import GenerateClientCertificateRequest


@dataclass
class MockedK8s:
    fetch_certificate_key_pair: Mock
    fetch_certificate_only: Mock


@pytest.fixture
def k8s_mock() -> Generator[MockedK8s, None, None]:
    with (
        patch("cactus_orchestrator.api.certificate.fetch_certificate_key_pair") as fetch_certificate_key_pair,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_only") as fetch_certificate_only,
    ):
        yield MockedK8s(
            fetch_certificate_key_pair=fetch_certificate_key_pair, fetch_certificate_only=fetch_certificate_only
        )


@pytest.mark.parametrize("run_group_id, is_device_cert", product([1, 2], [True, False]))
async def test_generate_new_certificate_and_fetch(
    client,
    pg_base_config,
    valid_jwt_user1,
    k8s_mock,
    mca_cert_key_pair,
    mica_cert_key_pair,
    run_group_id,
    is_device_cert,
):

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

    k8s_mock.fetch_certificate_key_pair.side_effect = mocked_fetch_certificate_key_pair
    k8s_mock.fetch_certificate_only.side_effect = mocked_fetch_certificate_only

    async with generate_async_session(pg_base_config) as session:
        original_cert_id = (
            (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id)))
            .scalar_one()
            .certificate_id
        )

    # Act
    body = GenerateClientCertificateRequest(is_device_cert=is_device_cert).model_dump()
    res = await client.put(
        f"/run_group/{run_group_id}/certificate", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, json=body
    )

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content and len(res.content)
    assert res.headers["content-type"] == "application/zip"
    assert res.headers["content-disposition"] and "attachment; filename=" in res.headers["content-disposition"]

    k8s_mock.fetch_certificate_key_pair.assert_called_once()
    k8s_mock.fetch_certificate_only.assert_called_once()

    # Decompose the resulting ZIP file
    zip = zipfile.ZipFile(io.BytesIO(res.content))

    cert_bytes = zip.read("certificate.pem")
    cert_chain_bytes = zip.read("fullchain.pem")
    key_bytes = zip.read("key.pem")
    pfx_bytes = zip.read("certificate.pfx")

    # Ensure it's all valid encodings
    cert = x509.load_pem_x509_certificate(cert_bytes)
    cert_chain = x509.load_pem_x509_certificates(cert_chain_bytes)
    pfx_key, pfx_cert, pfx_additional_certs = pkcs12.load_key_and_certificates(pfx_bytes, None)

    # Do some basic sanity checks
    assert cert_chain == [cert, mica_cert_key_pair[0], mca_cert_key_pair[0]]
    assert pfx_cert == cert
    assert pfx_additional_certs == [mica_cert_key_pair[0], mca_cert_key_pair[0]]
    assert (
        pfx_key.private_bytes(Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        == key_bytes
    )

    # Validate database got stored data
    async with generate_async_session(pg_base_config) as session:
        run_group = (
            await session.execute(
                select(RunGroup)
                .where(RunGroup.run_group_id == run_group_id)
                .options(
                    undefer(RunGroup.certificate_pem),
                )
            )
        ).scalar_one()

        assert run_group.certificate_pem == cert_bytes
        assert_nowish(run_group.certificate_generated_at)
        assert run_group.is_device_cert == is_device_cert
        assert run_group.certificate_id == (original_cert_id + 1)

    # Refetch and ensure the cert bytes match what we originally received
    res = await client.get(
        f"/run_group/{run_group_id}/certificate", headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )
    assert res.status_code == HTTPStatus.OK
    assert res.content and len(res.content)
    assert res.headers["content-type"] == MEDIA_TYPE_PEM_CRT
    assert res.content == cert_chain_bytes


@pytest.mark.parametrize("run_group_id", [3, 99])
@pytest.mark.asyncio
async def test_generate_new_certificate_bad_run_group_id(client, valid_jwt_user1, k8s_mock, run_group_id: int):
    """Test that regenerating a cert that DNE results in a failure"""
    # Arrange

    # Act
    body = GenerateClientCertificateRequest(is_device_cert=True).model_dump()
    res = await client.put(
        f"/run_group/{run_group_id}/certificate", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, json=body
    )

    # Assert
    assert res.status_code == HTTPStatus.FORBIDDEN

    k8s_mock.fetch_certificate_key_pair.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_current_certificate_authority_der(
    client, valid_jwt_user1, k8s_mock: MockedK8s, serca_cert_key_pair
):
    """Basic success path test."""

    # Arrange
    k8s_mock.fetch_certificate_only.return_value = serca_cert_key_pair[0]

    # Act
    response_1 = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response_1.status_code == HTTPStatus.OK
    assert response_1.headers["content-type"] == "application/x-x509-ca-cert"
    assert x509.load_pem_x509_certificate(response_1.content, default_backend()) == serca_cert_key_pair[0]

    response_2 = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response_2.status_code == HTTPStatus.OK
    assert response_2.headers["content-type"] == "application/x-x509-ca-cert"
    assert x509.load_pem_x509_certificate(response_2.content, default_backend()) == serca_cert_key_pair[0]

    # Assert
    k8s_mock.fetch_certificate_only.call_count == 2
