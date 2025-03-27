import base64
import logging
from http import HTTPStatus
from typing import Annotated

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.crud import insert_user, select_user, update_user
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair
from cactus_orchestrator.schema import UserContext, UserResponse
from cactus_orchestrator.settings import TEST_CLIENT_P12_PASSWORD, main_settings

logger = logging.getLogger(__name__)


router = APIRouter()


def create_client_cert_binary(user_context: UserContext) -> tuple[bytes, bytes]:
    # create client certificate
    ca_cert, ca_key = fetch_certificate_key_pair(main_settings.tls_ca_tls_secret_name)  # TODO: cache this
    client_p12, client_cert = generate_client_p12(
        ca_cert=ca_cert,
        ca_key=ca_key,
        client_common_name=user_context.subject_id,
        p12_password=TEST_CLIENT_P12_PASSWORD.get_secret_value(),
    )
    return client_p12, client_cert.public_bytes(encoding=serialization.Encoding.DER)


@router.patch("/user", status_code=HTTPStatus.OK)
async def update_existing_user_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserResponse:
    # create certs
    client_p12, client_x509_der = create_client_cert_binary(user_context)

    user_id = await update_user(db.session, user_context, client_p12, client_x509_der)

    if user_id is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="User does not exists. Please register.")

    await db.session.commit()
    return UserResponse(
        user_id=user_id,
        certificate_p12_b64=base64.b64encode(client_p12).decode("utf-8"),
        password=TEST_CLIENT_P12_PASSWORD,
    )


# NOTE: For simplicity, we've decided to not have separate POST/create endpoint for
# registering a new user.
@router.get("/user", status_code=HTTPStatus.OK)
async def get_user(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserResponse:
    """For simplicity, this endpoint both fetches and implicitly registers a 'new' user based on their valid JWT."""

    user = await select_user(db.session, user_context)

    if user is None:
        logger.info(f"Registering new user {user_context}")

        # create certs
        client_p12, client_x509_der = create_client_cert_binary(user_context)

        # write user
        user = await insert_user(db.session, user_context, client_p12, client_x509_der)

        await db.session.commit()

    return UserResponse(
        user_id=user.user_id,
        certificate_p12_b64=base64.b64encode(user.certificate_p12_bundle).decode("utf-8"),
        password=TEST_CLIENT_P12_PASSWORD,
    )
