import logging
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.run import select_user_or_raise
from cactus_orchestrator.auth import AuthScopes, jwt_validator
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

    static_uri: str | None = None
    if user.is_static_uri:
        static_uri = generate_envoy_dcap_uri(generate_static_test_stack_id(user))

    return UserConfigurationResponse(
        subscription_domain="" if user.subscription_domain is None else user.subscription_domain,
        is_static_uri=user.is_static_uri,
        static_uri=static_uri,
    )


@router.get("/config")
async def fetch_existing_config(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserConfigurationResponse:
    user = await select_user_or_raise(db.session, user_context)
    return user_to_config(user)


@router.post("/config", status_code=HTTPStatus.CREATED)
async def update_config(
    body: UserConfigurationRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserConfigurationResponse:
    user = await select_user_or_raise(db.session, user_context)

    if body.subscription_domain:
        parsed_domain = parse_domain(body.subscription_domain)
        if not parsed_domain:
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Expected a FQDN like 'my.example.domain'")
        user.subscription_domain = parsed_domain
    else:
        user.subscription_domain = None
    user.is_static_uri = body.is_static_uri
    await db.session.commit()

    return user_to_config(user)
