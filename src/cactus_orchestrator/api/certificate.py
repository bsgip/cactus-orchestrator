import io
import logging
import re
import zipfile
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Annotated

from cactus_schema.orchestrator import (
    CertificateRequest,
    CertificateResponse,
    Pagination,
    RunGroupCertificateAssignRequest,
    RunGroupResponse,
    uri,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.common import (
    select_user_certificate_or_raise,
    select_user_or_raise,
    select_user_run_group_or_raise,
)
from cactus_orchestrator.api.pagination import PageParams, build_page
from cactus_orchestrator.api.run_group import map_group_to_group_response
from cactus_orchestrator.audit import audit_log
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.certificate.create import generate_aggregator_certificate, generate_device_certificate
from cactus_orchestrator.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only, fetch_pem_bundle
from cactus_orchestrator.crud import (
    count_certificates_for_user,
    select_active_run_ids_for_certificate,
    select_certificates_for_user,
    select_run_group_counts_for_user,
    unlink_runs_from_certificate,
)
from cactus_orchestrator.model import AuditChangeType, Certificate, RunGroup, User
from cactus_orchestrator.settings import CactusOrchestratorSettings, get_current_settings

logger = logging.getLogger(__name__)

router = APIRouter()

MEDIA_TYPE_P12 = "application/x-pkcs12"
MEDIA_TYPE_CA_CRT = "application/x-x509-ca-cert"
# The following media types taken from https://pki-tutorial.readthedocs.io/en/latest/mime.html
MEDIA_TYPE_PEM_CRT = "application/x-x509-user-cert"
MEDIA_TYPE_PEM_KEY = "application/pkcs8"


def _filename_safe(value: str) -> str:
    """Certificate names are user supplied - flatten anything unusual so it's safe to use in a filename/header."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def _cert_label(is_device_cert: bool) -> str:
    return "Device" if is_device_cert else "Aggregator"


def _cert_identifier(certificate: Certificate) -> str:
    """Unique identifier (encoded into the EE certificate hwSerialNum) for the current generation of certificate"""
    return f"c-{certificate.certificate_id}-{_cert_label(certificate.is_device_cert)}-{certificate.generation}"


def _validate_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Certificate name must not be empty.")
    return name


def _map_certificate_response(certificate: Certificate) -> CertificateResponse:
    """Requires Certificate.certificate_pem and Certificate.run_groups to be populated"""
    client_cert = x509.load_pem_x509_certificate(certificate.certificate_pem)
    return CertificateResponse(
        certificate_id=certificate.certificate_id,
        name=certificate.name,
        is_device_cert=certificate.is_device_cert,
        created_at=certificate.created_at,
        generated_at=certificate.generated_at,
        expires_at=client_cert.not_valid_after_utc,
        generation=certificate.generation,
        run_group_ids=sorted(rg.run_group_id for rg in certificate.run_groups),
    )


def _certificate_zip_response(certificate: Certificate, zip_bytes: bytes, status_code: HTTPStatus) -> Response:
    label = _cert_label(certificate.is_device_cert)
    filename = f"{_filename_safe(certificate.name)}-{label}-certificates-{certificate.generation}.zip"
    return Response(
        status_code=status_code,
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Location": uri.Certificate.format(certificate_id=certificate.certificate_id),
        },
    )


def _chain_certs_for(settings: CactusOrchestratorSettings, is_device_cert: bool) -> list[x509.Certificate]:
    """Returns the intermediate CA chain (nearest issuer first, excluding SERCA) for the requested EE chain.

    device:     [Device MICA, Device MCA]
    aggregator: [Agg ICA, Agg PCA]
    """
    if is_device_cert:
        mica_cert, _ = fetch_certificate_key_pair(
            settings.cert_device_mica_crt_path, settings.cert_device_mica_key_path
        )
        return [mica_cert, fetch_certificate_only(settings.cert_device_mca_path)]

    ica_cert, _ = fetch_certificate_key_pair(settings.cert_agg_ica_crt_path, settings.cert_agg_ica_key_path)
    return [ica_cert, fetch_certificate_only(settings.cert_agg_pca_path)]


def _issue_certificate(
    settings: CactusOrchestratorSettings, user: User, is_device_cert: bool, cert_identifier: str
) -> tuple[bytes, bytes]:
    """Mints a new EE certificate on the appropriate chain.

    Returns (client_cert_pem, zip_bytes): the EE certificate PEM to persist on the Certificate, and the downloadable ZIP
    bundle (see _build_certificate_zip).
    """
    if is_device_cert:
        mca_cert = fetch_certificate_only(settings.cert_device_mca_path)
        mica_cert, mica_key = fetch_certificate_key_pair(
            settings.cert_device_mica_crt_path, settings.cert_device_mica_key_path
        )
        client_key, client_cert = generate_device_certificate(mica_key, mica_cert, user.pen, cert_identifier)
        chain_certs = [mica_cert, mca_cert]
    else:
        if not user.subscription_domain:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Set a notification/subscription domain before generating an aggregator certificate.",
            )
        pca_cert = fetch_certificate_only(settings.cert_agg_pca_path)
        ica_cert, ica_key = fetch_certificate_key_pair(settings.cert_agg_ica_crt_path, settings.cert_agg_ica_key_path)
        client_key, client_cert = generate_aggregator_certificate(
            ica_key, ica_cert, user.pen, cert_identifier, user.subscription_domain
        )
        chain_certs = [ica_cert, pca_cert]

    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = client_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fullchain_pem = client_cert_pem + b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain_certs)
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=cert_identifier.encode(),
        key=client_key,
        cert=client_cert,
        cas=chain_certs,
        encryption_algorithm=serialization.NoEncryption(),
    )

    zip_bytes = _build_certificate_zip(fullchain_pem, key_pem, pfx_bytes)
    return client_cert_pem, zip_bytes


def _build_certificate_zip(fullchain_pem: bytes, key_pem: bytes, pfx_bytes: bytes) -> bytes:
    """Bundles the issued certificate material into a ZIP:

    fullchain.pem    # PEM EE certificate + intermediate CA chain (excluding SERCA)
    key.pem          # PEM encoded private key (unencrypted)
    certificate.pfx  # PKCS12 encoded EE certificate + CA chain + private key (unencrypted)
    """
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr("fullchain.pem", fullchain_pem)
        zip_file.writestr("key.pem", key_pem)
        zip_file.writestr("certificate.pfx", pfx_bytes)
    return zip_buffer.getvalue()


@router.get(
    uri.CertificateAuthority,
    status_code=HTTPStatus.OK,
    response_class=Response,
)
async def fetch_utility_server_certificates(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:
    """Fetches everything an OEM needs to trust the utility server (envoy) when it acts as the mTLS client POSTing
    notifications to the OEM's webhook - the SERCA trust anchor plus the envoy (DNSP) signing chain.

    Returns a ZIP stream of bytes with the following files:

        serca.pem                      # PEM encoded SERCA (trust anchor to install in the OEM trust store)
        utility-server-fullchain.pem   # PEM encoded envoy EE + envoy ICA + envoy PCA chain (excluding SERCA)
    """
    settings = get_current_settings()
    serca_pem = fetch_certificate_only(settings.cert_serca_path).public_bytes(serialization.Encoding.PEM)
    # The fullchain (EE + DNSP ICA + DNSP PCA) is the pre-assembled bundle from create-cert.sh - served verbatim.
    fullchain_pem = fetch_pem_bundle(settings.cert_envoy_ee_fullchain_path)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr("serca.pem", serca_pem)
        zip_file.writestr("utility-server-fullchain.pem", fullchain_pem)

    return Response(
        status_code=HTTPStatus.OK,
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=utility-server-certificates.zip"},
    )


@router.get(uri.CertificateList, status_code=HTTPStatus.OK)
async def get_certificates_paginated(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    page_params: Annotated[PageParams, Depends()],
) -> Pagination[CertificateResponse]:
    """Lists the certificates owned by the current user (and which run groups they are assigned to)"""
    user = await select_user_or_raise(db.session, user_context)
    total = await count_certificates_for_user(db.session, user.user_id)
    certificates = await select_certificates_for_user(
        db.session, user.user_id, offset=page_params.offset, limit=page_params.limit
    )
    return build_page([_map_certificate_response(c) for c in certificates], total, page_params)


@router.post(
    uri.CertificateList,
    status_code=HTTPStatus.CREATED,
    response_class=Response,
)
async def create_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    body: CertificateRequest,
) -> Response:
    """Generates a brand new certificate for the current user (not assigned to any run groups).

    Will return a ZIP stream of bytes (see _build_certificate_zip). The Location header will reference the new
    certificate. The private key is NOT stored - this (and regeneration) are the only opportunities to obtain it.
    """
    user = await select_user_or_raise(db.session, user_context)
    name = _validate_name(body.name)

    # Insert first (with a placeholder PEM) so the certificate_id can be encoded into the certificate identifier
    certificate = Certificate(
        user_id=user.user_id,
        name=name,
        is_device_cert=body.is_device_cert,
        certificate_pem=b"",
        generated_at=datetime.now(UTC),
        generation=1,
    )
    db.session.add(certificate)
    await db.session.flush()

    identifier = _cert_identifier(certificate)
    client_cert_pem, zip_bytes = _issue_certificate(
        get_current_settings(), user, body.is_device_cert, cert_identifier=identifier
    )
    certificate.certificate_pem = client_cert_pem

    audit_log(
        db.session,
        user.user_id,
        AuditChangeType.CERTIFICATE_CREATED,
        certificate.certificate_id,
        f"Created {_cert_label(body.is_device_cert)} certificate {identifier} {name!r}",
    )
    await db.session.commit()

    return _certificate_zip_response(certificate, zip_bytes, HTTPStatus.CREATED)


@router.get(
    uri.Certificate,
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_PEM_CRT: {}}}},
)
async def fetch_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    certificate_id: int,
) -> Response:
    """Fetches the certificate as a raw binary response. This will also contain the intermediate CA signing chain
    (device or aggregator depending on the certificate). Certificate will be PEM encoded."""
    _, certificate = await select_user_certificate_or_raise(db.session, user_context, certificate_id)

    chain_certs = _chain_certs_for(get_current_settings(), certificate.is_device_cert)
    client_cert = x509.load_pem_x509_certificate(certificate.certificate_pem)

    # We just concatenate our PEM encodings together
    filename = f"{_filename_safe(certificate.name)}-fullchain-{certificate.generation}.pem"
    return Response(
        status_code=HTTPStatus.OK,
        content=client_cert.public_bytes(serialization.Encoding.PEM)
        + b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain_certs),
        media_type=MEDIA_TYPE_PEM_CRT,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.put(
    uri.Certificate,
    status_code=HTTPStatus.OK,
    response_class=Response,
)
async def regenerate_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    certificate_id: int,
) -> Response:
    """Regenerates an existing certificate (same name/type), replacing the existing certificate for every run group it
    is assigned to.

    Will return a ZIP stream of bytes (see _build_certificate_zip).
    """
    # Lock the row so concurrent regeneration serialises the generation counter
    user, certificate = await select_user_certificate_or_raise(
        db.session, user_context, certificate_id, for_update=True
    )

    certificate.generation = certificate.generation + 1
    identifier = _cert_identifier(certificate)
    client_cert_pem, zip_bytes = _issue_certificate(
        get_current_settings(), user, certificate.is_device_cert, cert_identifier=identifier
    )
    certificate.certificate_pem = client_cert_pem
    certificate.generated_at = datetime.now(UTC)

    audit_log(
        db.session,
        user.user_id,
        AuditChangeType.CERTIFICATE_REGENERATED,
        certificate.certificate_id,
        f"Regenerated {_cert_label(certificate.is_device_cert)} certificate {identifier}",
    )
    await db.session.commit()

    return _certificate_zip_response(certificate, zip_bytes, HTTPStatus.OK)


@router.delete(uri.Certificate, status_code=HTTPStatus.NO_CONTENT)
async def delete_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    certificate_id: int,
) -> None:
    """Deletes a certificate - any run groups it's assigned to will be left without a certificate and any (finalised)
    runs that used it will no longer reference it. Will fail with CONFLICT if any active runs are using it."""
    # Lock the row - run creation (FK on run.certificate_id) will block behind this until we commit/rollback
    user, certificate = await select_user_certificate_or_raise(
        db.session, user_context, certificate_id, for_update=True
    )

    active_run_ids = await select_active_run_ids_for_certificate(db.session, certificate_id)
    if active_run_ids:
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail=f"Cannot delete certificate {certificate_id} while it's in use by active run(s) "
            f"{', '.join(str(i) for i in active_run_ids)}. Finalise those runs first.",
        )

    # Historical runs - the FK is ON DELETE SET NULL but it's done explicitly so the change can be audited
    unlinked_run_ids = await unlink_runs_from_certificate(db.session, certificate_id)
    if unlinked_run_ids:
        audit_log(
            db.session,
            user.user_id,
            AuditChangeType.RUN_UPDATED,
            unlinked_run_ids,
            f"Unlinked certificate {certificate_id} from finalised runs (certificate deleted)",
        )

    run_group_ids = sorted(rg.run_group_id for rg in certificate.run_groups)
    for run_group in certificate.run_groups:
        run_group.certificate_id = None
    if run_group_ids:
        await db.session.flush()  # Ensure the FK references are cleared before deleting
        audit_log(
            db.session,
            user.user_id,
            AuditChangeType.RUN_GROUP_CERTIFICATE_ASSIGNED,
            run_group_ids,
            f"Unassigned certificate {certificate_id} (certificate deleted)",
        )

    await db.session.delete(certificate)
    audit_log(
        db.session,
        user.user_id,
        AuditChangeType.CERTIFICATE_DELETED,
        certificate_id,
        f"Deleted certificate {certificate_id} {certificate.name!r}",
    )
    await db.session.commit()


async def _set_run_group_certificate(
    user: User, run_group: RunGroup, certificate: Certificate | None
) -> RunGroupResponse:
    """Updates the assigned certificate for run_group, commits and returns the updated RunGroupResponse."""
    old_certificate_id = run_group.certificate_id
    new_certificate_id = certificate.certificate_id if certificate else None
    if old_certificate_id != new_certificate_id:
        # Existing runs keep the certificate they were created with - this only affects runs created from now on
        run_group.certificate = certificate
        audit_log(
            db.session,
            user.user_id,
            AuditChangeType.RUN_GROUP_CERTIFICATE_ASSIGNED,
            run_group.run_group_id,
            f"Certificate assignment {old_certificate_id} -> {new_certificate_id}",
        )
    await db.session.commit()

    run_counts = await select_run_group_counts_for_user(db.session, [run_group.run_group_id])
    settings = get_current_settings()
    return map_group_to_group_response(
        run_group, settings.cactus_fqdn, settings.envoy_prefix, run_counts.get(run_group.run_group_id, 0)
    )


@router.put(uri.RunGroupCertificate, status_code=HTTPStatus.OK)
async def assign_run_group_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
    body: RunGroupCertificateAssignRequest,
) -> RunGroupResponse:
    """Assigns an existing certificate (owned by the same user) to a run group, replacing any existing assignment.
    Existing runs (including in progress playlists) will continue to use the certificate they were created with."""
    user, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)
    _, certificate = await select_user_certificate_or_raise(
        db.session,
        user_context,
        body.certificate_id,
        for_update=True,  # Lock - prevents a concurrent delete
    )
    return await _set_run_group_certificate(user, run_group, certificate)


@router.delete(uri.RunGroupCertificate, status_code=HTTPStatus.OK)
async def unassign_run_group_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
) -> RunGroupResponse:
    """Removes any certificate assignment from a run group (the certificate itself is NOT deleted). Existing runs
    (including in progress playlists) will continue to use the certificate they were created with."""
    user, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)
    return await _set_run_group_certificate(user, run_group, None)
