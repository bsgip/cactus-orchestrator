import io
import zipfile
from collections.abc import Generator
from dataclasses import dataclass
from http import HTTPStatus
from unittest.mock import Mock, patch

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import (
    CertificateRequest,
    CertificateResponse,
    RunGroupCertificateAssignRequest,
    RunGroupResponse,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, pkcs12
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import undefer

from cactus_orchestrator.api.certificate import MEDIA_TYPE_PEM_CRT
from cactus_orchestrator.model import AuditChangeType, Certificate, Run, RunGroup
from tests.utils.audit import assert_audit_logs


@dataclass
class MockedCertFetch:
    fetch_certificate_key_pair: Mock
    fetch_certificate_only: Mock
    fetch_pem_bundle: Mock


@pytest.fixture
def k8s_mock() -> Generator[MockedCertFetch, None, None]:
    with (
        patch("cactus_orchestrator.api.certificate.fetch_certificate_key_pair") as fetch_certificate_key_pair,
        patch("cactus_orchestrator.api.certificate.fetch_certificate_only") as fetch_certificate_only,
        patch("cactus_orchestrator.api.certificate.fetch_pem_bundle") as fetch_pem_bundle,
    ):
        yield MockedCertFetch(
            fetch_certificate_key_pair=fetch_certificate_key_pair,
            fetch_certificate_only=fetch_certificate_only,
            fetch_pem_bundle=fetch_pem_bundle,
        )


@pytest.fixture
def cert_mock(k8s_mock, mca_cert_key_pair, mica_cert_key_pair) -> MockedCertFetch:
    """The only part we mock is the fetching of signing certs from disk"""
    k8s_mock.fetch_certificate_key_pair.return_value = mica_cert_key_pair
    k8s_mock.fetch_certificate_only.return_value = mca_cert_key_pair[0]
    return k8s_mock


def auth(jwt: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {jwt}"}


def decompose_zip(content: bytes, mca_cert_key_pair, mica_cert_key_pair) -> tuple[x509.Certificate, bytes]:
    """Validates the certificate ZIP bundle - returns the EE cert and the fullchain.pem bytes"""
    zip = zipfile.ZipFile(io.BytesIO(content))
    cert_chain_bytes = zip.read("fullchain.pem")
    key_bytes = zip.read("key.pem")
    pfx_bytes = zip.read("certificate.pfx")

    cert_chain = x509.load_pem_x509_certificates(cert_chain_bytes)
    cert = cert_chain[0]
    pfx_key, pfx_cert, pfx_additional_certs = pkcs12.load_key_and_certificates(pfx_bytes, None)
    assert pfx_key is not None

    assert cert_chain == [cert, mica_cert_key_pair[0], mca_cert_key_pair[0]]
    assert pfx_cert == cert
    assert pfx_additional_certs == [mica_cert_key_pair[0], mca_cert_key_pair[0]]
    assert (
        pfx_key.private_bytes(Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        == key_bytes
    )
    return cert, cert_chain_bytes


async def set_real_pems(pg_config, pem: bytes) -> None:
    """The base_config certificates have junk PEM values - replace them with something parseable"""
    async with generate_async_session(pg_config) as session:
        await session.execute(update(Certificate).values(certificate_pem=pem))
        await session.commit()


async def get_certificate(pg_config, certificate_id: int) -> Certificate | None:
    async with generate_async_session(pg_config) as session:
        return (
            await session.execute(
                select(Certificate)
                .where(Certificate.certificate_id == certificate_id)
                .options(undefer(Certificate.certificate_pem))
            )
        ).scalar_one_or_none()


async def get_run_group_certificate_id(pg_config, run_group_id: int) -> int | None:
    async with generate_async_session(pg_config) as session:
        return (
            await session.execute(select(RunGroup.certificate_id).where(RunGroup.run_group_id == run_group_id))
        ).scalar_one()


@pytest.mark.parametrize("is_device_cert", [True, False])
async def test_create_certificate_and_fetch(
    client, pg_base_config, valid_jwt_user1, cert_mock, mca_cert_key_pair, mica_cert_key_pair, is_device_cert
):
    # Act
    body = CertificateRequest(name=" My Cert/1 ", is_device_cert=is_device_cert).to_json()
    res = await client.post("/certificate", headers=auth(valid_jwt_user1), content=body)

    # Assert
    assert res.status_code == HTTPStatus.CREATED, res.text
    assert res.headers["content-type"] == "application/zip"
    label = "Device" if is_device_cert else "Aggregator"
    assert res.headers["content-disposition"] == f"attachment; filename=My_Cert_1-{label}-certificates-1.zip"
    assert res.headers["location"] == "/certificate/4"  # base_config has 3 certificates

    cert, cert_chain_bytes = decompose_zip(res.content, mca_cert_key_pair, mica_cert_key_pair)

    db_cert = await get_certificate(pg_base_config, 4)
    assert db_cert is not None
    assert db_cert.user_id == 1
    assert db_cert.name == "My Cert/1"
    assert db_cert.is_device_cert is is_device_cert
    assert db_cert.certificate_pem == cert.public_bytes(Encoding.PEM)
    assert db_cert.generation == 1
    assert_nowish(db_cert.created_at)
    assert_nowish(db_cert.generated_at)

    # New certs are NOT assigned to anything
    for run_group_id in [1, 2]:
        assert (await get_run_group_certificate_id(pg_base_config, run_group_id)) != 4

    # Refetch and ensure the cert bytes match what we originally received
    res = await client.get("/certificate/4", headers=auth(valid_jwt_user1))
    assert res.status_code == HTTPStatus.OK
    assert res.headers["content-type"] == MEDIA_TYPE_PEM_CRT
    assert res.headers["content-disposition"] == "attachment; filename=My_Cert_1-fullchain-1.pem"
    assert res.content == cert_chain_bytes

    await assert_audit_logs(pg_base_config, [(1, AuditChangeType.CERTIFICATE_CREATED, [4])])


@pytest.mark.parametrize(
    "jwt_fixture, name, is_device_cert",
    [
        ("valid_jwt_user1", "", True),
        ("valid_jwt_user1", "   ", False),
        ("valid_jwt_user3", "agg cert", False),  # user3 has no subscription domain - can't make an aggregator cert
    ],
)
async def test_create_certificate_bad_request(
    client, pg_base_config, request, cert_mock, jwt_fixture, name, is_device_cert
):
    jwt = request.getfixturevalue(jwt_fixture)
    body = CertificateRequest(name=name, is_device_cert=is_device_cert).to_json()
    res = await client.post("/certificate", headers=auth(jwt), content=body)

    assert res.status_code == HTTPStatus.BAD_REQUEST, res.text
    async with generate_async_session(pg_base_config) as session:
        assert (await session.execute(select(func.count()).select_from(Certificate))).scalar_one() == 3
    await assert_audit_logs(pg_base_config, [])


async def test_get_certificates_paginated(client, pg_base_config, valid_jwt_user1, mica_cert_key_pair):
    mica_cert = mica_cert_key_pair[0]
    await set_real_pems(pg_base_config, mica_cert.public_bytes(Encoding.PEM))

    res = await client.get("/certificate", headers=auth(valid_jwt_user1))
    assert res.status_code == HTTPStatus.OK, res.text
    data = res.json()
    assert data["total_items"] == 2
    items = CertificateResponse.from_list(data["items"])
    assert [i.certificate_id for i in items] == [1, 3]
    assert [i.name for i in items] == ["cert-1", "cert-3"]
    assert [i.is_device_cert for i in items] == [True, False]
    assert [i.generation for i in items] == [11, 4]
    assert [i.run_group_ids for i in items] == [[1], []]
    assert all(i.expires_at == mica_cert.not_valid_after_utc for i in items)

    res = await client.get("/certificate?page=2&size=1", headers=auth(valid_jwt_user1))
    assert res.status_code == HTTPStatus.OK
    assert [i.certificate_id for i in CertificateResponse.from_list(res.json()["items"])] == [3]


async def test_get_certificates_paginated_empty(client, pg_base_config, valid_jwt_user3):
    res = await client.get("/certificate", headers=auth(valid_jwt_user3))
    assert res.status_code == HTTPStatus.OK, res.text
    assert res.json()["items"] == []


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
@pytest.mark.parametrize("certificate_id", [2, 99])  # 2 is owned by user 2
async def test_certificate_wrong_user(client, pg_base_config, valid_jwt_user1, cert_mock, method, certificate_id):
    res = await client.request(method, f"/certificate/{certificate_id}", headers=auth(valid_jwt_user1))
    assert res.status_code == HTTPStatus.NOT_FOUND, res.text
    cert_mock.fetch_certificate_key_pair.assert_not_called()
    assert (await get_certificate(pg_base_config, 2)) is not None
    await assert_audit_logs(pg_base_config, [])


async def test_regenerate_certificate(
    client, pg_base_config, valid_jwt_user1, cert_mock, mca_cert_key_pair, mica_cert_key_pair
):
    """Regenerating certificate 1 (device, generation 11, assigned to run group 1) - active runs don't block this"""
    res = await client.put("/certificate/1", headers=auth(valid_jwt_user1))

    assert res.status_code == HTTPStatus.OK, res.text
    assert res.headers["content-type"] == "application/zip"
    assert res.headers["content-disposition"] == "attachment; filename=cert-1-Device-certificates-12.zip"
    assert res.headers["location"] == "/certificate/1"
    cert, cert_chain_bytes = decompose_zip(res.content, mca_cert_key_pair, mica_cert_key_pair)

    db_cert = await get_certificate(pg_base_config, 1)
    assert db_cert is not None
    assert db_cert.certificate_pem == cert.public_bytes(Encoding.PEM)
    assert db_cert.generation == 12
    assert db_cert.is_device_cert is True
    assert db_cert.name == "cert-1"
    assert_nowish(db_cert.generated_at)
    assert (await get_run_group_certificate_id(pg_base_config, 1)) == 1, "Assignment is unchanged"

    # The run group should report the new generation time
    res = await client.get("/run_group", headers=auth(valid_jwt_user1))
    rg = RunGroupResponse.from_dict(res.json()["items"][0])
    assert rg.run_group_id == 1 and rg.assigned_certificate_id == 1
    assert_nowish(rg.certificate_created_at)

    res = await client.get("/certificate/1", headers=auth(valid_jwt_user1))
    assert res.content == cert_chain_bytes

    await assert_audit_logs(pg_base_config, [(1, AuditChangeType.CERTIFICATE_REGENERATED, [1])])


async def link_runs_to_certificate(pg_config, run_ids: list[int], certificate_id: int) -> None:
    async with generate_async_session(pg_config) as session:
        await session.execute(update(Run).where(Run.run_id.in_(run_ids)).values(certificate_id=certificate_id))
        await session.commit()


async def get_run_certificate_ids(pg_config) -> dict[int, int | None]:
    async with generate_async_session(pg_config) as session:
        return {
            run_id: cert_id for run_id, cert_id in (await session.execute(select(Run.run_id, Run.certificate_id))).all()
        }


@pytest.mark.parametrize(
    "certificate_id, linked_run_ids, expected_status, expected_unassigned_run_group_ids, expected_unlinked_run_ids",
    [
        (3, [], HTTPStatus.NO_CONTENT, [], []),  # unassigned + unused
        (1, [], HTTPStatus.NO_CONTENT, [1], []),  # assigned to run group 1 (which has active runs NOT using cert 1)
        (1, [2, 3], HTTPStatus.NO_CONTENT, [1], [2, 3]),  # used by finalised runs 2, 3
        (3, [4], HTTPStatus.NO_CONTENT, [], [4]),  # unassigned but used by finalised run 4
        (1, [2, 8], HTTPStatus.CONFLICT, [], []),  # used by active run 8
        (3, [5], HTTPStatus.CONFLICT, [], []),  # unassigned but used by active run 5
    ],
)
async def test_delete_certificate(
    client,
    pg_base_config,
    valid_jwt_user1,
    certificate_id,
    linked_run_ids,
    expected_status,
    expected_unassigned_run_group_ids,
    expected_unlinked_run_ids,
):
    # base_config: runs 1, 5, 6, 8 are active, runs 2, 3, 4, 7 are finalised
    await link_runs_to_certificate(pg_base_config, linked_run_ids, certificate_id)

    res = await client.delete(f"/certificate/{certificate_id}", headers=auth(valid_jwt_user1))
    assert res.status_code == expected_status, res.text

    run_cert_ids = await get_run_certificate_ids(pg_base_config)
    if expected_status == HTTPStatus.NO_CONTENT:
        assert (await get_certificate(pg_base_config, certificate_id)) is None
        for run_group_id in expected_unassigned_run_group_ids:
            assert (await get_run_group_certificate_id(pg_base_config, run_group_id)) is None
        assert all(run_cert_ids[run_id] is None for run_id in linked_run_ids)

        expected_logs = []
        if expected_unlinked_run_ids:
            expected_logs.append((1, AuditChangeType.RUN_UPDATED, expected_unlinked_run_ids))
        if expected_unassigned_run_group_ids:
            expected_logs.append((1, AuditChangeType.RUN_GROUP_CERTIFICATE_ASSIGNED, expected_unassigned_run_group_ids))
        expected_logs.append((1, AuditChangeType.CERTIFICATE_DELETED, [certificate_id]))
        await assert_audit_logs(pg_base_config, expected_logs)
    else:
        assert (await get_certificate(pg_base_config, certificate_id)) is not None
        assert (await get_run_group_certificate_id(pg_base_config, 1)) == 1
        assert all(run_cert_ids[run_id] == certificate_id for run_id in linked_run_ids)
        await assert_audit_logs(pg_base_config, [])


@pytest.mark.parametrize(
    "run_group_id, certificate_id, expected_status, expected_certificate_id, expect_audit",
    [
        (1, 3, HTTPStatus.OK, 3, True),  # Swap certificate (run group 1 has active runs - that's fine)
        (2, 1, HTTPStatus.OK, 1, True),  # Share cert 1 between run group 1 and 2
        (1, 1, HTTPStatus.OK, 1, False),  # No change
        (1, 2, HTTPStatus.NOT_FOUND, 1, False),  # Cert 2 belongs to user 2
        (1, 99, HTTPStatus.NOT_FOUND, 1, False),  # Cert DNE
        (3, 1, HTTPStatus.FORBIDDEN, 2, False),  # Run group 3 belongs to user 2
    ],
)
async def test_assign_run_group_certificate(
    client,
    pg_base_config,
    valid_jwt_user1,
    mica_cert_key_pair,
    run_group_id,
    certificate_id,
    expected_status,
    expected_certificate_id,
    expect_audit,
):
    # Existing runs (active or not) should never be affected by assignment changes
    await link_runs_to_certificate(pg_base_config, [1, 2], 1)
    run_cert_ids_before = await get_run_certificate_ids(pg_base_config)

    body = RunGroupCertificateAssignRequest(certificate_id=certificate_id).to_json()
    res = await client.put(f"/run_group/{run_group_id}/certificate", headers=auth(valid_jwt_user1), content=body)
    assert res.status_code == expected_status, res.text

    assert (await get_run_group_certificate_id(pg_base_config, run_group_id)) == expected_certificate_id
    assert (await get_run_certificate_ids(pg_base_config)) == run_cert_ids_before
    if expected_status == HTTPStatus.OK:
        rg = RunGroupResponse.from_json(res.text)
        assert rg.run_group_id == run_group_id
        assert rg.assigned_certificate_id == certificate_id
        db_cert = await get_certificate(pg_base_config, certificate_id)
        assert db_cert is not None
        assert rg.certificate_name == db_cert.name
        assert rg.is_device_cert == db_cert.is_device_cert
        assert rg.certificate_created_at == db_cert.generated_at

    if expect_audit:
        await assert_audit_logs(pg_base_config, [(1, AuditChangeType.RUN_GROUP_CERTIFICATE_ASSIGNED, [run_group_id])])
    else:
        await assert_audit_logs(pg_base_config, [])

    if run_group_id == 2 and expected_status == HTTPStatus.OK:
        # Validate the sharing is visible in the certificate listing
        await set_real_pems(pg_base_config, mica_cert_key_pair[0].public_bytes(Encoding.PEM))
        res = await client.get("/certificate", headers=auth(valid_jwt_user1))
        items = CertificateResponse.from_list(res.json()["items"])
        assert [i.run_group_ids for i in items] == [[1, 2], []]


@pytest.mark.parametrize(
    "run_group_id, expected_status, expected_certificate_id, expect_audit",
    [
        (1, HTTPStatus.OK, None, True),  # Run group 1 has active runs - that's fine
        (2, HTTPStatus.OK, None, False),  # Already unassigned
        (3, HTTPStatus.FORBIDDEN, 2, False),  # Run group 3 belongs to user 2
    ],
)
async def test_unassign_run_group_certificate(
    client,
    pg_base_config,
    valid_jwt_user1,
    run_group_id,
    expected_status,
    expected_certificate_id,
    expect_audit,
):
    await link_runs_to_certificate(pg_base_config, [1, 2], 1)
    run_cert_ids_before = await get_run_certificate_ids(pg_base_config)

    res = await client.delete(f"/run_group/{run_group_id}/certificate", headers=auth(valid_jwt_user1))
    assert res.status_code == expected_status, res.text

    assert (await get_run_group_certificate_id(pg_base_config, run_group_id)) == expected_certificate_id
    assert (await get_run_certificate_ids(pg_base_config)) == run_cert_ids_before
    if expected_status == HTTPStatus.OK:
        rg = RunGroupResponse.from_json(res.text)
        assert rg.assigned_certificate_id is None
        assert rg.certificate_name is None
        assert rg.is_device_cert is None
        assert rg.certificate_created_at is None

    # Certificates are never deleted by unassignment
    async with generate_async_session(pg_base_config) as session:
        assert (await session.execute(select(func.count()).select_from(Certificate))).scalar_one() == 3

    if expect_audit:
        await assert_audit_logs(pg_base_config, [(1, AuditChangeType.RUN_GROUP_CERTIFICATE_ASSIGNED, [run_group_id])])
    else:
        await assert_audit_logs(pg_base_config, [])


async def test_run_group_cannot_reference_other_users_certificate(pg_base_config):
    """The composite FK should prevent cross user certificate references at the DB level"""
    async with generate_async_session(pg_base_config) as session:
        with pytest.raises(IntegrityError):
            await session.execute(update(RunGroup).where(RunGroup.run_group_id == 1).values(certificate_id=2))


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

    # Arrange - the endpoint reads the SERCA cert and the pre-assembled envoy EE fullchain bundle (paths are mocked)
    serca_cert = serca_cert_key_pair[0]
    envoy_pca_cert = services_pca_cert_key_pair[0]
    envoy_ica_cert = dnsp_ica_cert_key_pair[0]
    envoy_ee_cert = envoy_ee_cert_key_pair[0]
    fullchain = (
        envoy_ee_cert.public_bytes(Encoding.PEM)
        + envoy_ica_cert.public_bytes(Encoding.PEM)
        + envoy_pca_cert.public_bytes(Encoding.PEM)
    )
    k8s_mock.fetch_certificate_only.return_value = serca_cert
    k8s_mock.fetch_pem_bundle.return_value = fullchain

    # Act
    response = await client.get("/certificate/authority", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"] == "application/zip"
    assert "filename=utility-server-certificates.zip" in response.headers["content-disposition"]

    zip = zipfile.ZipFile(io.BytesIO(response.content))
    assert set(zip.namelist()) == {"serca.pem", "utility-server-fullchain.pem"}
    assert x509.load_pem_x509_certificate(zip.read("serca.pem"), default_backend()) == serca_cert
    # The fullchain bundle (envoy EE + ICA + PCA, SERCA excluded) is served verbatim
    assert x509.load_pem_x509_certificates(zip.read("utility-server-fullchain.pem")) == [
        envoy_ee_cert,
        envoy_ica_cert,
        envoy_pca_cert,
    ]
    k8s_mock.fetch_certificate_only.assert_called_once()  # SERCA
    k8s_mock.fetch_pem_bundle.assert_called_once()  # envoy fullchain
