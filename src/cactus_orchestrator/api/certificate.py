import logging
from http import HTTPStatus
from typing import Annotated, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.crud import select_user, upsert_user
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only
from cactus_orchestrator.manager.certificate import CertificateManager
from cactus_orchestrator.schema import UserContext
from cactus_orchestrator.settings import TEST_CLIENT_P12_PASSWORD, CactusOrchestratorException, main_settings

logger = logging.getLogger(__name__)


router = APIRouter()


MEDIA_TYPE_P12 = "application/x-pkcs12"
MEDIA_TYPE_CA_CRT = "application/x-x509-ca-cert"


@router.get(
    "/certificate",
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_P12: {}}}},
)
async def get_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    try:
        client_p12 = CertificateManager.fetch_existing_certificate_p12(db.session, user_context)

    except CactusOrchestratorException as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.CONFLICT)

    return Response(
        content=client_p12,
        media_type=MEDIA_TYPE_P12,
    )


@router.post(
    "/certificate/generate",
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={
        HTTPStatus.OK: {
            "headers": {"X-Certificate-Password": {"description": "Password for .p12 certificate bundle."}},
            "content": {MEDIA_TYPE_P12: {}},
        }
    },
)
async def create_user_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    client_p12 = await CertificateManager.create_user_certificate(db.session, user_context)

    return Response(
        content=client_p12,
        media_type=MEDIA_TYPE_P12,
        headers={"X-Certificate-Password": TEST_CLIENT_P12_PASSWORD.get_secret_value()},
    )


@router.get(
    "/certificate/authority",
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_CA_CRT: {}}}},
)
async def get_certificate_authority(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    # fastapi should raise 500 if this fails
    ca_cert = await CertificateManager.fetch_current_certificate_authority_der()

    return Response(
        content=ca_cert.public_bytes(serialization.Encoding.DER),
        media_type=MEDIA_TYPE_CA_CRT,
    )
