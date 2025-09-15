from http import HTTPStatus
import logging
from typing import Annotated
from cactus_orchestrator.crud import select_user, update_user_name
from cactus_orchestrator.schema import UserContext, UserUpdateRequest
from cactus_orchestrator.auth import AuthPerm, jwt_validator
from fastapi_async_sqlalchemy import db
from fastapi import APIRouter, Depends
from fastapi import HTTPException

logger = logging.getLogger(__name__)


router = APIRouter()


@router.patch("/user", status_code=HTTPStatus.OK)
async def patch_user_name(
    body: UserUpdateRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> bool:

    user = await select_user(db.session, user_context)
    if user is None:
        logger.error(
            (
                "Unable to update user."
                f" User not found subject_id={user_context.subject_id}"
                f" issuer_id={user_context.issuer_id}."
            )
        )
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail=f"User '{user_context.subject_id}' not found.")

    try:
        await update_user_name(session=db.session, user_id=user.user_id, user_name=body.user_name)
        await db.session.commit()
    except Exception as e:
        logger.error("Exception occurred when updating user name", exc_info=e)
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Unable to update username of '{user_context.subject_id}.",
        )

    return True
