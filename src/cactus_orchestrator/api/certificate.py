import logging
from enum import StrEnum, auto
from http import HTTPStatus
from typing import Annotated, Any

import shortuuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db
from pydantic import SecretStr

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.crud import insert_user, select_user
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only
from cactus_orchestrator.schema import UserContext
from cactus_orchestrator.settings import CactusOrchestratorException, get_current_settings

logger = logging.getLogger(__name__)


class CertificateRouteType(StrEnum):
    aggregator = auto()
    device = auto()


router = APIRouter()


MEDIA_TYPE_P12 = "application/x-pkcs12"
MEDIA_TYPE_CA_CRT = "application/x-x509-ca-cert"


async def update_ca_certificate_cache(_: Any) -> dict[str, ExpiringValue[x509.Certificate]]:
    cert = await fetch_certificate_only(get_current_settings().tls_ca_certificate_generic_secret_name)

    return {_ca_crt_cachekey: ExpiringValue(expiry=cert.not_valid_after_utc, value=cert)}


# NOTE: do not log.
_ca_crt_cachekey = ""
_ca_crt_cache = AsyncCache(update_fn=update_ca_certificate_cache, force_update_delay_seconds=60)


async def create_client_cert_binary(
    user_context: UserContext, client_cert_passphrase: SecretStr
) -> tuple[bytes, bytes]:
    ca_cert, ca_key = await fetch_certificate_key_pair(get_current_settings().tls_ca_tls_secret_name)

    # create client certificate
    client_p12, client_cert = generate_client_p12(
        ca_cert=ca_cert,
        ca_key=ca_key,
        client_common_name=user_context.subject_id,
        p12_password=client_cert_passphrase.get_secret_value(),
    )
    return client_p12, client_cert.public_bytes(encoding=serialization.Encoding.DER)


@router.get(
    "/certificate/authority",
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_CA_CRT: {}}}},
)
async def fetch_current_certificate_authority_der(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    # fetch ca
    ca_cert = await _ca_crt_cache.get_value(None, _ca_crt_cachekey)

    if ca_cert is None:
        raise CactusOrchestratorException("CA certificate not found.")

    return Response(
        content=ca_cert.public_bytes(serialization.Encoding.DER),
        media_type=MEDIA_TYPE_CA_CRT,
    )


@router.get(
    "/certificate/{cert_type}",
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {MEDIA_TYPE_P12: {}}}},
)
async def fetch_client_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
    cert_type: str,
) -> Response:
    """Fetches the certificate as a p12/pfx encoded stream of bytes

    cert_type=device Returns the device certificate
    cert_type=aggregator Returns the aggregator certificate"""

    if cert_type == CertificateRouteType.aggregator:
        with_aggregator_p12 = True
        with_device_p12 = False
    elif cert_type == CertificateRouteType.device:
        with_aggregator_p12 = False
        with_device_p12 = True
    else:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"cert_type '{cert_type}' is not valid. Please use 'aggregator' or 'device'",
        )

    # get user with the appropriate p12 selected
    user = await select_user(
        db.session, user_context, with_aggregator_p12=with_aggregator_p12, with_device_p12=with_device_p12
    )
    if user is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="No certificate exists, please register.")

    # Extract the appropriate stream of bytes
    if cert_type == CertificateRouteType.aggregator:
        return Response(
            content=user.aggregator_certificate_p12_bundle,
            media_type=MEDIA_TYPE_P12,
        )
    elif cert_type == CertificateRouteType.device:
        return Response(
            content=user.device_certificate_p12_bundle,
            media_type=MEDIA_TYPE_P12,
        )
    else:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"cert_type '{cert_type}' is not valid. Please use 'aggregator' or 'device'",
        )


@router.put(
    "/certificate/{cert_type}",
    status_code=HTTPStatus.OK,
    response_class=Response,
    responses={
        HTTPStatus.OK: {
            "headers": {"X-Certificate-Password": {"description": "Password for .p12 certificate bundle."}},
            "content": {MEDIA_TYPE_P12: {}},
        }
    },
)
async def generate_client_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
    cert_type: str,
) -> Response:
    """Generates a user's certificate of cert_type. Replacing any existing certificate details

    cert_type=device Returns the device certificate
    cert_type=aggregator Returns the aggregator certificate"""

    if cert_type not in CertificateRouteType:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"cert_type '{cert_type}' is not valid. Please use 'aggregator' or 'device'",
        )

    # Get (or create) the user
    user = await select_user(db.session, user_context)
    if user is None:
        user = await insert_user(db.session, user_context)
        logger.info(f"Created new user {user.user_id} for user context {user_context}")

    # generate client passphrase
    pass_phrase = SecretStr(shortuuid.random(length=20))
    client_p12, client_x509_der = await create_client_cert_binary(user_context, pass_phrase)

    # update the certificate details on the user
    if cert_type == CertificateRouteType.aggregator:
        user.aggregator_certificate_p12_bundle = client_p12
        user.aggregator_certificate_x509_der = client_x509_der
    elif cert_type == CertificateRouteType.device:
        user.device_certificate_p12_bundle = client_p12
        user.device_certificate_x509_der = client_x509_der
    else:
        # Check above should've prevented this from happening
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"cert_type '{cert_type}' is not valid. Please use 'aggregator' or 'device'",
        )

    await db.session.commit()

    return Response(
        content=client_p12,
        media_type=MEDIA_TYPE_P12,
        headers={"X-Certificate-Password": pass_phrase.get_secret_value()},
    )
