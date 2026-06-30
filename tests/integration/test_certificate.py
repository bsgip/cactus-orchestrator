import io
import zipfile
from collections.abc import Generator
from dataclasses import dataclass
from http import HTTPStatus
from itertools import product
from unittest.mock import Mock, patch

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import GenerateClientCertificateRequest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, pkcs12
from sqlalchemy import select
from sqlalchemy.orm import undefer

from cactus_orchestrator.api.certificate import MEDIA_TYPE_PEM_CRT
from cactus_orchestrator.model import RunGroup


@dataclass
class MockedCertFetch:
    fetch_certificate_key_pair: Mock
    fetch_certificate_only: Mock


@pytest.fixture
def k8s_mock() -> Generator[MockedCertFetch, None, None]:
    with (
        patch("cactus_orchestrator.api.certificate.fetch_certificate_key_pair") as fetch_certificate_key_pair,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_only") as fetch_certificate_only,
    ):
        yield MockedCertFetch(
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

    # The only part we mock is the fetching of certs from disk
    k8s_mock.fetch_certificate_key_pair.return_value = mica_cert_key_pair
    k8s_mock.fetch_certificate_only.return_value = mca_cert_key_pair[0]

    async with generate_async_session(pg_base_config) as session:
        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        original_cert_id = run_group.certificate_id
        csip_aus_version = run_group.csip_aus_version

    # Act
    body = GenerateClientCertificateRequest(is_device_cert=is_device_cert).to_json()
    res = await client.put(
        f"/run_group/{run_group_id}/certificate", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, content=body
    )

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content and len(res.content)
    assert res.headers["content-type"] == "application/zip"
    assert res.headers["content-disposition"] and "attachment; filename=" in res.headers["content-disposition"]
    # csip aus version (slash-sanitised) is appended to the download filename
    assert res.headers["content-disposition"].endswith(f"-{csip_aus_version.replace('/', '-')}.zip")

    k8s_mock.fetch_certificate_key_pair.assert_called_once()
    k8s_mock.fetch_certificate_only.assert_called_once()

    # Decompose the resulting ZIP file
    zip = zipfile.ZipFile(io.BytesIO(res.content))
    cert_chain_bytes = zip.read("fullchain.pem")
    key_bytes = zip.read("key.pem")
    pfx_bytes = zip.read("certificate.pfx")

    # Ensure it's all valid encodings
    cert_chain = x509.load_pem_x509_certificates(cert_chain_bytes)
    cert = cert_chain[0]  # Extract cert from the chain as we no longer save to zip
    pfx_key, pfx_cert, pfx_additional_certs = pkcs12.load_key_and_certificates(pfx_bytes, None)
    assert pfx_key is not None

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
        cert_bytes = cert.public_bytes(Encoding.PEM)
        assert run_group.certificate_pem == cert_bytes
        assert run_group.certificate_generated_at is not None
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
    body = GenerateClientCertificateRequest(is_device_cert=True).to_json()
    res = await client.put(
        f"/run_group/{run_group_id}/certificate",
        headers={"Authorization": f"Bearer {valid_jwt_user1}", "Content-Type": "application/json"},
        content=body,
    )

    # Assert
    assert res.status_code == HTTPStatus.FORBIDDEN, res.text

    k8s_mock.fetch_certificate_key_pair.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_utility_server_certificates(
    client,
    valid_jwt_user1,
    k8s_mock: MockedCertFetch,
    serca_cert_key_pair,
    services_pca_cert_key_pair,
    dnsp_ica_cert_key_pair,
    envoy_ee_cert_key_pair,
):
    """The /certificate/authority endpoint returns the SERCA + envoy chain bundle as a zip."""

    # Arrange - the endpoint fetches (in order) SERCA, envoy PCA, envoy ICA, envoy EE (paths are mocked)
    serca_cert = serca_cert_key_pair[0]
    envoy_pca_cert = services_pca_cert_key_pair[0]
    envoy_ica_cert = dnsp_ica_cert_key_pair[0]
    envoy_ee_cert = envoy_ee_cert_key_pair[0]
    k8s_mock.fetch_certificate_only.side_effect = [serca_cert, envoy_pca_cert, envoy_ica_cert, envoy_ee_cert]

    # Act
    response = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"] == "application/zip"
    assert "filename=utility-server-certificates.zip" in response.headers["content-disposition"]

    zip = zipfile.ZipFile(io.BytesIO(response.content))
    assert set(zip.namelist()) == {"serca.pem", "utility-server-fullchain.pem"}
    assert x509.load_pem_x509_certificate(zip.read("serca.pem"), default_backend()) == serca_cert
    # The fullchain is the envoy EE concatenated with its ICA then PCA (SERCA excluded - it's the separate trust anchor)
    assert x509.load_pem_x509_certificates(zip.read("utility-server-fullchain.pem")) == [
        envoy_ee_cert,
        envoy_ica_cert,
        envoy_pca_cert,
    ]
    # serca + envoy pca/ica/ee
    assert k8s_mock.fetch_certificate_only.call_count == 4


async def test_generate_shared_aggregator_certificate_and_fetch(
    client,
    pg_base_config,
    valid_jwt_user1,
    k8s_mock,
    mca_cert_key_pair,
    mica_cert_key_pair,
):

    user_id = 1  # This needs to match the `valid_jwt_user?` fixture used.

    # The only part we mock is the fetching of certs from disk
    k8s_mock.fetch_certificate_key_pair.return_value = mica_cert_key_pair
    k8s_mock.fetch_certificate_only.return_value = mca_cert_key_pair[0]

    async with generate_async_session(pg_base_config) as session:
        run_groups = (await session.execute(select(RunGroup).where(RunGroup.user_id == user_id))).scalars().all()
    original_certificate_ids = [r.certificate_id for r in run_groups]
    max_original_certificate_id = max(original_certificate_ids)
    run_group_ids = [r.run_group_id for r in run_groups]

    # Act
    res = await client.put("/run_group/certificate", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.content and len(res.content)
    assert res.headers["content-type"] == "application/zip"
    assert res.headers["content-disposition"] and "attachment; filename=" in res.headers["content-disposition"]

    k8s_mock.fetch_certificate_key_pair.assert_called_once()
    k8s_mock.fetch_certificate_only.assert_called_once()

    # Decompose the resulting ZIP file
    zip = zipfile.ZipFile(io.BytesIO(res.content))
    cert_chain_bytes = zip.read("fullchain.pem")
    key_bytes = zip.read("key.pem")
    pfx_bytes = zip.read("certificate.pfx")

    # Ensure it's all valid encodings
    cert_chain = x509.load_pem_x509_certificates(cert_chain_bytes)
    cert = cert_chain[0]  # Extract cert from the chain as we no longer save to zip
    pfx_key, pfx_cert, pfx_additional_certs = pkcs12.load_key_and_certificates(pfx_bytes, None)
    assert pfx_key is not None

    # Do some basic sanity checks
    assert cert_chain == [cert, mica_cert_key_pair[0], mca_cert_key_pair[0]]
    assert pfx_cert == cert
    assert pfx_additional_certs == [mica_cert_key_pair[0], mca_cert_key_pair[0]]
    assert (
        pfx_key.private_bytes(Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        == key_bytes
    )

    # Validate database got stored data
    for run_group_id in run_group_ids:
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
            cert_bytes = cert.public_bytes(Encoding.PEM)
            assert run_group.certificate_pem == cert_bytes
            assert run_group.certificate_generated_at is not None
            assert_nowish(run_group.certificate_generated_at)
            assert not run_group.is_device_cert  # must be an aggregator cert if shared
            assert run_group.certificate_id == max_original_certificate_id + 1

        # Refetch and ensure the cert bytes match what we originally received
        res = await client.get(
            f"/run_group/{run_group_id}/certificate", headers={"Authorization": f"Bearer {valid_jwt_user1}"}
        )
        assert res.status_code == HTTPStatus.OK
        assert res.content and len(res.content)
        assert res.headers["content-type"] == MEDIA_TYPE_PEM_CRT
        assert res.content == cert_chain_bytes
