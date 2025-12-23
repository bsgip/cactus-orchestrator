import logging
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urlparse

from cactus_schema.orchestrator import UserConfigurationRequest, UserConfigurationResponse, uri
from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.common import select_user_or_create
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.k8s.resource import generate_envoy_dcap_uri, generate_static_test_stack_id, get_resource_names
from cactus_orchestrator.model import User

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
        static_uri = generate_envoy_dcap_uri(get_resource_names(generate_static_test_stack_id(user)))

    return UserConfigurationResponse(
        subscription_domain="" if user.subscription_domain is None else user.subscription_domain,
        is_static_uri=user.is_static_uri,
        static_uri=static_uri,
        pen=0 if user.pen is None else user.pen,
    )


@router.get(uri.Config)
async def fetch_existing_config(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> UserConfigurationResponse:
    user = await select_user_or_create(db.session, user_context)
    result = user_to_config(user)
    await db.session.commit()  # We need to commit in case this is a new user
    return result


@router.post(uri.Config, status_code=HTTPStatus.CREATED)
async def update_config(
    body: UserConfigurationRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
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

    if body.pen is not None:
        user.pen = body.pen

    await db.session.commit()

    return user_to_config(user)
