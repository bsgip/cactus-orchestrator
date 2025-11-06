import logging
from datetime import datetime, timezone
from enum import StrEnum, auto
from http import HTTPStatus
from typing import Annotated, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.common import select_user_run_group_or_raise
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.k8s.certificate.create import generate_client_p12_ec
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only
from cactus_orchestrator.settings import CactusOrchestratorException, get_current_settings

logger = logging.getLogger(__name__)


class CertificateComponent(StrEnum):
    certificate = auto()  # PEM encoded certificate (contains MCA/MICA)
    key = auto()  # PEM encoded private key (no password / encryption)
    p12 = auto()  # pkcs12 (p12) encoded certificate (with MCA/MICA) + key (no password / encryption)


class CertificateType(StrEnum):
    aggregator = auto()
    device = auto()


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


@router.get("/run_group/{run_group_id}/certificate/{cert_component}", response_class=Response)
async def fetch_client_certificate_component(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
    cert_component: CertificateComponent,
) -> Response:
    """Fetches a specific part of the run group's certificate as a raw binary response. See CertComponent for the
    various things that can be downloaded."""
    user, run_group = await select_user_run_group_or_raise(
        db.session, user_context, run_group_id, with_cert_key_values=True
    )

    if run_group.certificate_pem is None or run_group.key_pem is None:
        logger.info(f"user {user.user_id} run_group {run_group_id} does NOT have a certificate yet.")
        return Response(
            status_code=HTTPStatus.BAD_REQUEST,
            content=f"No certificate stored for run group {run_group_id}. Generate a certificate first.",
            media_type="text/plain",
        )

    # Key downloads are easy - just send it straight from the DB
    if cert_component == CertificateComponent.key:
        return Response(status_code=HTTPStatus.OK, content=run_group.key_pem, media_type=MEDIA_TYPE_PEM_KEY)

    # cert / p12 downloads will require the MICA / MCA signing chain
    settings = get_current_settings()
    mica_cert, _ = await fetch_certificate_key_pair(settings.tls_mica_secret_name)
    mca_cert = await fetch_certificate_only(settings.cert_mca_secret_name)
    client_cert = x509.load_pem_x509_certificate(run_group.certificate_pem)

    if cert_component == CertificateComponent.p12:
        # We just generate the pfx from the various certs
        client_key = cast(
            ec.EllipticCurvePrivateKey, serialization.load_pem_private_key(run_group.key_pem, password=None)
        )
        pfx_data: bytes = pkcs12.serialize_key_and_certificates(
            name=f"({run_group_id}) {run_group.name}".encode(),
            key=client_key,
            cert=client_cert,
            cas=[mica_cert, mca_cert],
            encryption_algorithm=serialization.NoEncryption(),
        )
        return Response(status_code=HTTPStatus.OK, content=pfx_data, media_type=MEDIA_TYPE_P12)
    elif cert_component == CertificateComponent.certificate:
        # We just concatenate our PEM encodings together
        return Response(
            status_code=HTTPStatus.OK,
            content=client_cert.public_bytes(serialization.Encoding.PEM)
            + mica_cert.public_bytes(serialization.Encoding.PEM)
            + mca_cert.public_bytes(serialization.Encoding.PEM),
            media_type=MEDIA_TYPE_PEM_CRT,
        )
    else:
        logger.info(f"user {user.user_id} run_group {run_group_id} requested bad cert_component '{cert_component}'.")
        return Response(
            status_code=HTTPStatus.BAD_REQUEST,
            content=f"Unsupported cert_component '{cert_component}'",
            media_type="text/plain",
        )


@router.put(
    "/run_group/{run_group_id}/certificate",
    status_code=HTTPStatus.OK,
    response_class=Response,
)
async def generate_client_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
    cert_type: str | None = None,  # Query parameter
) -> Response:
    """Generates a user's certificate of cert_type. Replacing any existing certificate details

    ?cert_type=device Generates a device certificate
    ?cert_type=aggregator Generates a aggregator certificate"""

    if cert_type is None or cert_type not in CertificateType:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Query param cert_type '{cert_type}' is not valid. Please use 'aggregator' or 'device'",
        )

    # Get the user / run_group
    _, run_group = await select_user_run_group_or_raise(
        db.session, user_context, run_group_id, with_cert_key_values=True
    )

    now = datetime.now(timezone.utc)

    # Generate the cert
    common_name = f"{cert_type} {run_group.name} {run_group.csip_aus_version}"
    identifier = f"rg-{run_group_id}-ts-{now.timestamp()}"
    settings = get_current_settings()
    mica_cert, mica_key = await fetch_certificate_key_pair(settings.tls_mica_secret_name)
    client_key, client_cert = generate_client_p12_ec(mica_key, mica_cert, common_name, identifier)

    # update the certificate details on the run group
    run_group.certificate_generated_at = now
    run_group.is_device_cert = cert_type == CertificateType.device
    run_group.certificate_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    run_group.key_pem = client_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    await db.session.commit()

    return Response(status_code=HTTPStatus.CREATED)
