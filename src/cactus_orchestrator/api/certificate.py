import io
import logging
import zipfile
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Annotated

from cactus_schema.orchestrator import GenerateClientCertificateRequest, uri
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.common import select_user_run_group_or_raise, select_user_run_groups_or_raise
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.certificate.create import generate_aggregator_certificate, generate_device_certificate
from cactus_orchestrator.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only
from cactus_orchestrator.model import User
from cactus_orchestrator.settings import CactusOrchestratorError, CactusOrchestratorSettings, get_current_settings

logger = logging.getLogger(__name__)

router = APIRouter()

MEDIA_TYPE_P12 = "application/x-pkcs12"
MEDIA_TYPE_CA_CRT = "application/x-x509-ca-cert"
# The following media types taken from https://pki-tutorial.readthedocs.io/en/latest/mime.html
MEDIA_TYPE_PEM_CRT = "application/x-x509-user-cert"
MEDIA_TYPE_PEM_KEY = "application/pkcs8"


def _filename_safe(value: str) -> str:
    """csip_aus_version values can contain a slash (e.g. 'v1.3-beta/storage') - flatten it for use in a filename."""
    return value.replace("/", "-")


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


def _issue_run_group_certificate(
    settings: CactusOrchestratorSettings, user: User, is_device_cert: bool, cert_identifier: str
) -> tuple[x509.Certificate, bytes, bytes, bytes]:
    """Mints a new EE certificate for a run group on the appropriate chain.

    Returns (client_cert, client_cert_pem, key_pem, fullchain_pem) where fullchain_pem is the EE concatenated with its
    intermediate CA chain (excluding SERCA).
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
    return client_cert, client_cert_pem, fullchain_pem, zip_bytes


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
    serca_cert = fetch_certificate_only(settings.cert_serca_path)
    if serca_cert is None:
        raise CactusOrchestratorError("SERCA certificate not found.")
    envoy_pca_cert = fetch_certificate_only(settings.cert_envoy_pca_path)
    envoy_ica_cert = fetch_certificate_only(settings.cert_envoy_ica_path)
    envoy_ee_cert = fetch_certificate_only(settings.cert_envoy_ee_crt_path)

    fullchain = (
        envoy_ee_cert.public_bytes(serialization.Encoding.PEM)
        + envoy_ica_cert.public_bytes(serialization.Encoding.PEM)
        + envoy_pca_cert.public_bytes(serialization.Encoding.PEM)
    )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr("serca.pem", serca_cert.public_bytes(serialization.Encoding.PEM))
        zip_file.writestr("utility-server-fullchain.pem", fullchain)

    return Response(
        status_code=HTTPStatus.OK,
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=utility-server-certificates.zip"},
    )


@router.get(
    uri.CertificateRunGroup,
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_PEM_CRT: {}}}},
)
async def fetch_client_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
) -> Response:
    """Fetches the most recent run group's certificate as a raw binary response. This will also contain the intermediate
    CA signing chain (device or aggregator depending on the stored certificate). Certificate will be PEM encoded."""
    user, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id, with_cert=True)

    if run_group.certificate_pem is None or run_group.is_device_cert is None:
        logger.info(f"user {user.user_id} run_group {run_group_id} does NOT have a certificate yet.")
        return Response(
            status_code=HTTPStatus.BAD_REQUEST,
            content=f"No certificate stored for run group {run_group_id}. Generate a certificate first.",
            media_type="text/plain",
        )

    # cert downloads include the intermediate CA signing chain for the relevant cert type
    settings = get_current_settings()
    chain_certs = _chain_certs_for(settings, run_group.is_device_cert)
    client_cert = x509.load_pem_x509_certificate(run_group.certificate_pem)

    # We just concatenate our PEM encodings together
    filename = f"{run_group.name}-fullchain-{run_group.certificate_id}.pem"
    return Response(
        status_code=HTTPStatus.OK,
        content=client_cert.public_bytes(serialization.Encoding.PEM)
        + b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain_certs),
        media_type=MEDIA_TYPE_PEM_CRT,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.put(
    uri.CertificateRunGroups,
    status_code=HTTPStatus.OK,
    response_class=Response,
)
async def generate_shared_aggregator_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:
    """Generates an aggregator certificate and assigns it to all the users run groups
    replacing all existing certificates.

    Will return a ZIP stream of bytes (see _build_certificate_zip).
    """

    # Get the user / run_groups - lock the rows so concurrent generation serialises the certificate_id counter
    user, run_groups = await select_user_run_groups_or_raise(db.session, user_context, for_update=True)

    now = datetime.now(UTC)

    # Determine the certificate counter
    # note: different run groups might have different cert counters so bring them all to the
    # level of the run group with the maximum certificate counter
    max_cert_counter = max([run_group.certificate_id for run_group in run_groups])
    cert_counter = max_cert_counter + 1

    # Determine csip aus version identifier - run groups may differ, so collapse to a single value or "MIXED"
    csip_aus_versions = {run_group.csip_aus_version for run_group in run_groups}
    csip_aus_version = csip_aus_versions.pop() if len(csip_aus_versions) == 1 else "MIXED"

    # Generate the aggregator certificate
    cert_label = "Aggregator"
    run_group_name = "ALL"
    run_group_id = run_group_name
    identifier = f"rg-{run_group_id}-{cert_label}-{cert_counter}"
    settings = get_current_settings()
    client_cert, client_cert_pem, _, zip_bytes = _issue_run_group_certificate(
        settings, user, is_device_cert=False, cert_identifier=identifier
    )

    # update the certificate details for each run group
    for run_group in run_groups:
        run_group.certificate_generated_at = now
        run_group.is_device_cert = False  # Must be an aggregator certificate
        run_group.certificate_pem = client_cert_pem
        run_group.certificate_id = cert_counter
    await db.session.commit()

    return Response(
        status_code=HTTPStatus.OK,
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f"attachment; "
                f"filename={run_group_name}-{cert_label}-certificates-{cert_counter}-{_filename_safe(csip_aus_version)}.zip"
            )
        },
    )


@router.put(
    uri.CertificateRunGroup,
    status_code=HTTPStatus.OK,
    response_class=Response,
)
async def generate_client_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
    body: GenerateClientCertificateRequest,
) -> Response:
    """Generates a user's certificate based on GenerateClientCertificateRequest. Replacing any existing certificate
    details.

    Will return a ZIP stream of bytes (see _build_certificate_zip).
    """

    cert_label = "Device" if body.is_device_cert else "Aggregator"

    # Get the user / run_group - lock the row so concurrent generation serialises the certificate_id counter
    user, run_group = await select_user_run_group_or_raise(
        db.session, user_context, run_group_id, with_cert=True, for_update=True
    )

    now = datetime.now(UTC)

    # Generate the cert
    cert_counter = run_group.certificate_id + 1
    identifier = f"rg-{run_group_id}-{cert_label}-{cert_counter}"
    settings = get_current_settings()
    client_cert, client_cert_pem, _, zip_bytes = _issue_run_group_certificate(
        settings, user, body.is_device_cert, cert_identifier=identifier
    )

    # update the certificate details on the run group
    run_group.certificate_generated_at = now
    run_group.is_device_cert = body.is_device_cert
    run_group.certificate_pem = client_cert_pem
    run_group.certificate_id = cert_counter
    await db.session.commit()

    return Response(
        status_code=HTTPStatus.OK,
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f"attachment; filename={run_group.name}-{cert_label}-certificates-{cert_counter}"
                f"-{_filename_safe(run_group.csip_aus_version)}.zip"
            )
        },
    )
