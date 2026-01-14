import logging
from http import HTTPStatus

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.auth import UserContext
from cactus_orchestrator.crud import insert_user, select_run_group_for_user, select_run_groups_for_user, select_user
from cactus_orchestrator.model import RunGroup, User

logger = logging.getLogger(__name__)


async def select_user_or_create(session: AsyncSession, user_context: UserContext) -> User:
    """Fetches the user associated with user_context - creating one as required."""
    user = await select_user(session, user_context)
    if user is not None:
        return user

    user = await insert_user(session, user_context)
    logger.info(f"Created new user {user.user_id} for user context {user_context}")
    return user


async def select_user_or_raise(
    session: AsyncSession,
    user_context: UserContext,
) -> User:
    """Selects a user for the specific user context or raises a HTTPException if none can be found"""
    user = await select_user(session, user_context)

    if user is None:
        logger.error(f"Cannot find user for user context {user_context}")
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Certificate has not been registered.")
    return user


async def select_user_run_group_or_raise(
    session: AsyncSession, user_context: UserContext, run_group_id: int, with_cert: bool = False
) -> tuple[User, RunGroup]:
    """Selects a user for the specific user context AND their associated run_group_id or raises a HTTPException if none
    can be found.

    Can optionally include deferred certificate values on the RunGroup"""
    user = await select_user_or_raise(
        session,
        user_context,
    )

    run_group = await select_run_group_for_user(session, user.user_id, run_group_id, with_cert=with_cert)
    if run_group is None:
        logger.error(f"Cannot find run_group {run_group_id} for user {user.user_id}")
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail=f"Cannot find run_group {run_group_id} for user {user.user_id}"
        )

    return (user, run_group)


async def select_user_run_groups_or_raise(
    session: AsyncSession, user_context: UserContext
) -> tuple[User, list[RunGroup]]:
    """Selects a user for the specific user context AND their associated run_groups.

    Raises if the user not found."""

    user = await select_user_or_raise(session, user_context)

    run_groups = await select_run_groups_for_user(session, user.user_id)

    if not run_groups:
        logger.error(f"No run groups found for user {user.user_id}")
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail=f"Cannot find any run groups for user {user.user_id}"
        )

    return (user, list(run_groups))
