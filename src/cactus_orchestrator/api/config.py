import logging
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urlparse

from cactus_schema.orchestrator import UserConfigurationRequest, UserConfigurationResponse, uri
from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.common import select_user_or_create
from cactus_orchestrator.audit import audit_log
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.model import AuditChangeType, User

logger = logging.getLogger(__name__)


router = APIRouter()


def parse_domain(d: str) -> str:
    if ":" in d:
        return urlparse(d).netloc.split(":")[0]
    else:
        return d


def user_to_config(user: User) -> UserConfigurationResponse:
    """Requires aggregator_certificate_x509_der and device_certificate_x509_der to be undeferred"""

    return UserConfigurationResponse(
        subscription_domain="" if user.subscription_domain is None else user.subscription_domain,
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
    old_subscription_domain = user.subscription_domain
    old_pen = user.pen

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

    if body.pen is not None:
        user.pen = body.pen

    changes: list[str] = []
    if user.subscription_domain != old_subscription_domain:
        changes.append(f"subscription_domain {old_subscription_domain!r} -> {user.subscription_domain!r}")
    if user.pen != old_pen:
        changes.append(f"pen {old_pen} -> {user.pen}")
    if changes:
        audit_log(
            db.session,
            user.user_id,
            AuditChangeType.USER_UPDATED,
            user.user_id,
            f"Updated config: {', '.join(changes)}",
        )

    await db.session.commit()

    return user_to_config(user)
