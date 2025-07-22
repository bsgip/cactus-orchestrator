import logging
from datetime import datetime
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urlparse

from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.crud import insert_user, select_user
from cactus_orchestrator.k8s.run_id import generate_envoy_dcap_uri, generate_static_test_stack_id
from cactus_orchestrator.model import User
from cactus_orchestrator.schema import UserConfigurationRequest, UserConfigurationResponse, UserContext

logger = logging.getLogger(__name__)


router = APIRouter()


def parse_domain(d: str) -> str:
    if ":" in d:
        return urlparse(d).netloc.split(":")[0]
    else:
        return d


def user_to_config(user: User) -> UserConfigurationResponse:
    """Requires aggregator_certificate_x509_der and device_certificate_x509_der to be undeferred"""
    static_uri: str | None = None
    if user.is_static_uri:
        static_uri = generate_envoy_dcap_uri(generate_static_test_stack_id(user))

    aggregator_certificate_expiry: datetime | None = None
    if user.aggregator_certificate_x509_der:
        try:
            agg_cert = x509.load_der_x509_certificate(user.aggregator_certificate_x509_der)
            aggregator_certificate_expiry = agg_cert.not_valid_after_utc
        except Exception as exc:
            logger.error(f"Error interpreting aggregator client certificate for user {user.user_id}", exc_info=exc)

    device_certificate_expiry: datetime | None = None
    if user.device_certificate_x509_der:
        try:
            device_cert = x509.load_der_x509_certificate(user.device_certificate_x509_der)
            device_certificate_expiry = device_cert.not_valid_after_utc
        except Exception as exc:
            logger.error(f"Error interpreting device client certificate for user {user.user_id}", exc_info=exc)

    return UserConfigurationResponse(
        subscription_domain="" if user.subscription_domain is None else user.subscription_domain,
        is_static_uri=user.is_static_uri,
        static_uri=static_uri,
        is_device_cert=user.is_device_cert,
        aggregator_certificate_expiry=aggregator_certificate_expiry,
        device_certificate_expiry=device_certificate_expiry,
    )


async def select_user_or_create(session: AsyncSession, user_context: UserContext) -> User:
    """Fetches the user associated with user_context - creating one as required. Will include client certs"""
    user = await select_user(session, user_context, with_aggregator_der=True, with_device_der=True)
    if user is not None:
        return user

    user = await insert_user(session, user_context)
    logger.info(f"Created new user {user.user_id} for user context {user_context}")
    return user


@router.get("/config")
async def fetch_existing_config(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserConfigurationResponse:
    user = await select_user_or_create(db.session, user_context)
    result = user_to_config(user)
    await db.session.commit()  # We need to commit in case this is a new user
    return result


@router.post("/config", status_code=HTTPStatus.CREATED)
async def update_config(
    body: UserConfigurationRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserConfigurationResponse:
    user = await select_user_or_create(db.session, user_context)

    if body.subscription_domain is not None:
        if len(body.subscription_domain) == 0:
            user.subscription_domain = None
        else:
            parsed_domain = parse_domain(body.subscription_domain)
            if not parsed_domain:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST, detail="Expected a FQDN like 'my.example.domain'"
                )
            user.subscription_domain = parsed_domain

    if body.is_static_uri is not None:
        user.is_static_uri = body.is_static_uri

    if body.is_device_cert is not None:
        user.is_device_cert = body.is_device_cert

    await db.session.commit()

    return user_to_config(user)
