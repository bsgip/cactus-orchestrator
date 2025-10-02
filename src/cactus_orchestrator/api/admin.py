from http import HTTPStatus
import logging
from typing import Annotated
from cactus_orchestrator.crud import select_run_groups_by_user, select_users
from cactus_orchestrator.schema import UserWithRunGroupsResponse
from fastapi_pagination import Page, paginate
from cactus_orchestrator.auth import AuthPerm, jwt_validator, UserContext
from fastapi_async_sqlalchemy import db
from fastapi import APIRouter, Depends

logger = logging.getLogger(__name__)


router = APIRouter()


@router.get("/users", status_code=HTTPStatus.OK)
async def get_groups_paginated(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Page[UserWithRunGroupsResponse]:
    run_groups_by_user = await select_run_groups_by_user(db.session)
    users = await select_users(db.session)

    resp = [
        UserWithRunGroupsResponse(
            user_id=user.user_id,
            name=user.subject_id,
            run_groups=run_groups_by_user[user.user_id] if user.user_id in run_groups_by_user else [],
        )
        for user in users
    ]

    return paginate(resp)
