import logging
from http import HTTPStatus
from typing import Annotated, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.crud import upsert_user
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only
from cactus_orchestrator.schema import UserContext
from cactus_orchestrator.settings import TEST_CLIENT_P12_PASSWORD, CactusOrchestratorException, main_settings

logger = logging.getLogger(__name__)


router = APIRouter()


async def update_ca_certificate_cache(_: Any) -> dict[str, ExpiringValue[x509.Certificate]]:
    cert = await fetch_certificate_only(main_settings.tls_ca_certificate_generic_secret_name)

    return {_ca_crt_cachekey: ExpiringValue(expiry=cert.not_valid_after_utc, value=cert)}


# NOTE: do not log.
_ca_crt_cachekey = ""
_ca_crt_cache = AsyncCache(update_fn=update_ca_certificate_cache, force_update_delay_seconds=60)


async def create_client_cert_binary(user_context: UserContext) -> tuple[bytes, bytes]:
    ca_cert, ca_key = await fetch_certificate_key_pair(main_settings.tls_ca_tls_secret_name)  # TODO: cache maybe?

    # create client certificate
    client_p12, client_cert = generate_client_p12(
        ca_cert=ca_cert,
        ca_key=ca_key,
        client_common_name=user_context.subject_id,
        p12_password=TEST_CLIENT_P12_PASSWORD.get_secret_value(),
    )
    return client_p12, client_cert.public_bytes(encoding=serialization.Encoding.DER)


@router.post("/certificate/generate", status_code=HTTPStatus.OK)
async def create_user_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:
    # create certs
    client_p12, client_x509_der = await create_client_cert_binary(user_context)

    # insert or update user with new cert
    _ = await upsert_user(db.session, user_context, client_p12=client_p12, client_x509_der=client_x509_der)

    await db.session.commit()

    return Response(
        content=client_p12,
        media_type="application/x-pkcs12",
        headers={"X-Certificate-Password": TEST_CLIENT_P12_PASSWORD.get_secret_value()},
    )


@router.get("/certificate/authority", status_code=HTTPStatus.OK)
async def fetch_current_certificate_authority_der(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    # fetch ca
    ca_cert = await _ca_crt_cache.get_value(None, _ca_crt_cachekey)

    if ca_cert is None:
        raise CactusOrchestratorException("CA certificate not found.")

    return Response(
        content=ca_cert.public_bytes(serialization.Encoding.DER),
        media_type="application/x-x509-ca-cert",
    )
