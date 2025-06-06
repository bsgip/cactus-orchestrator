import logging
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.api.run import select_user_or_raise
from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.schema import UserContext, UserSubscriptionDomain

logger = logging.getLogger(__name__)


router = APIRouter()


def parse_domain(d: str) -> str:
    if ":" in d:
        return urlparse(d).netloc.split(":")[0]
    else:
        return d


@router.get("/domain")
async def fetch_existing_domain(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserSubscriptionDomain:
    user = await select_user_or_raise(db.session, user_context)
    return UserSubscriptionDomain(
        subscription_domain="" if user.subscription_domain is None else user.subscription_domain
    )


@router.post("/domain", status_code=HTTPStatus.CREATED)
async def create_subscription_domain(
    body: UserSubscriptionDomain,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserSubscriptionDomain:
    user = await select_user_or_raise(db.session, user_context)
    parsed_domain = parse_domain(body.subscription_domain)
    if not parsed_domain:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Expected a FQDN like 'my.example.domain'")
    user.subscription_domain = parsed_domain
    await db.session.commit()

    return UserSubscriptionDomain(subscription_domain=user.subscription_domain)
