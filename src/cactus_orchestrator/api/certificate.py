import io
import logging
import zipfile
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Annotated

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.common import select_user_run_group_or_raise
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.k8s.certificate.create import generate_client_p12_ec
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only
from cactus_orchestrator.schema import GenerateClientCertificateRequest
from cactus_orchestrator.settings import CactusOrchestratorException, get_current_settings

logger = logging.getLogger(__name__)

router = APIRouter()

MEDIA_TYPE_P12 = "application/x-pkcs12"
MEDIA_TYPE_CA_CRT = "application/x-x509-ca-cert"
# The following media types taken from https://pki-tutorial.readthedocs.io/en/latest/mime.html
MEDIA_TYPE_PEM_CRT = "application/x-x509-user-cert"
MEDIA_TYPE_PEM_KEY = "application/pkcs8"


@router.get(
    "/certificate/authority",
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_CA_CRT: {}}}},
)
async def fetch_current_certificate_authority_der(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:
    """Fetches a PEM encoded SERCA certificate (trust anchor for the signing chain)"""
    serca_cert = await fetch_certificate_only(get_current_settings().cert_serca_secret_name)
    if serca_cert is None:
        raise CactusOrchestratorException("SERCA certificate not found.")

    return Response(
        content=serca_cert.public_bytes(serialization.Encoding.PEM),
        media_type=MEDIA_TYPE_CA_CRT,
    )


@router.get(
    "/run_group/{run_group_id}/certificate",
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_PEM_CRT: {}}}},
)
async def fetch_client_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
) -> Response:
    """Fetches the most recent run group's certificate as a raw binary response. This will also contain the MICA/MCA
    as a full signing chain. Certificate will be PEM encoded."""
    user, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id, with_cert=True)

    if run_group.certificate_pem is None:
        logger.info(f"user {user.user_id} run_group {run_group_id} does NOT have a certificate yet.")
        return Response(
            status_code=HTTPStatus.BAD_REQUEST,
            content=f"No certificate stored for run group {run_group_id}. Generate a certificate first.",
            media_type="text/plain",
        )

    # cert / p12 downloads will require the MICA / MCA signing chain
    settings = get_current_settings()
    mica_cert, _ = await fetch_certificate_key_pair(settings.tls_mica_secret_name)
    mca_cert = await fetch_certificate_only(settings.cert_mca_secret_name)
    client_cert = x509.load_pem_x509_certificate(run_group.certificate_pem)

    # We just concatenate our PEM encodings together
    filename = f"{run_group.name}-fullchain-{run_group.certificate_id}.zip"
    return Response(
        status_code=HTTPStatus.OK,
        content=client_cert.public_bytes(serialization.Encoding.PEM)
        + mica_cert.public_bytes(serialization.Encoding.PEM)
        + mca_cert.public_bytes(serialization.Encoding.PEM),
        media_type=MEDIA_TYPE_PEM_CRT,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.put(
    "/run_group/{run_group_id}/certificate",
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

    Will return a ZIP stream of bytes with the following files:

        certificate.pem         # PEM encoded certificate
        fullchain.pem           # PEM encoded certificate + MICA/MCA certificate bundle chain
        key.pem                 # PEM encoded private key (unencrypted)
        certificate.pfx              # PKCS12 encoded certificate + MICA/MCA chain / private key (unencrypted)
    """

    cert_label = "Device" if body.is_device_cert else "Aggregator"

    # Get the user / run_group
    _, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id, with_cert=True)

    now = datetime.now(timezone.utc)

    # Generate the cert
    cert_counter = run_group.certificate_id + 1
    common_name = f"({cert_counter}) {cert_label} {run_group.name} {run_group.csip_aus_version}"
    identifier = f"rg-{run_group_id}-id-{cert_counter}"
    settings = get_current_settings()
    mca_cert = await fetch_certificate_only(settings.cert_mca_secret_name)
    mica_cert, mica_key = await fetch_certificate_key_pair(settings.tls_mica_secret_name)
    client_key, client_cert = generate_client_p12_ec(mica_key, mica_cert, common_name, identifier)

    # Generate the raw file data
    client_cert_bytes = client_cert.public_bytes(serialization.Encoding.PEM)
    mica_cert_bytes = mica_cert.public_bytes(serialization.Encoding.PEM)
    mca_cert_bytes = mca_cert.public_bytes(serialization.Encoding.PEM)
    client_key_bytes = client_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=common_name.encode(),
        key=client_key,
        cert=client_cert,
        cas=[mica_cert, mca_cert],
        encryption_algorithm=serialization.NoEncryption(),
    )

    # update the certificate details on the run group
    run_group.certificate_generated_at = now
    run_group.is_device_cert = body.is_device_cert
    run_group.certificate_pem = client_cert_bytes
    run_group.certificate_id = cert_counter  # This is only a best effort counter - can cause race conditions
    await db.session.commit()

    # generate output ZipFile
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr("certificate.pem", client_cert_bytes)
        zip_file.writestr("fullchain.pem", client_cert_bytes + mica_cert_bytes + mca_cert_bytes)
        zip_file.writestr("key.pem", client_key_bytes)
        zip_file.writestr("certificate.pfx", pfx_bytes)

    return Response(
        status_code=HTTPStatus.OK,
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={run_group.name}-{cert_label}-certificates-{cert_counter}.zip"
        },
    )
