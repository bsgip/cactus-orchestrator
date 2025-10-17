import pytest
from assertical.fixtures.postgres import generate_async_session
from fastapi.exceptions import HTTPException

from cactus_orchestrator.api.admin import (
    assume_user_context_from_run,
    assume_user_context_from_run_group,
    select_user_with_run_group_or_raise,
    select_user_with_run_or_raise,
)
from cactus_orchestrator.auth import AuthPerm, UserContext
from cactus_orchestrator.model import User


@pytest.mark.parametrize(
    "run_group_id, user_id",
    [
        (1, 1),
        (2, 1),
        (3, 2),
    ],
)
@pytest.mark.asyncio
async def test_select_user_with_run_group_or_raise(run_group_id: int, user_id: int | None, pg_base_config):
    async with generate_async_session(pg_base_config) as session:
        user = await select_user_with_run_group_or_raise(session=session, run_group_id=run_group_id)
        assert isinstance(user, User)
        assert user.user_id == user_id


@pytest.mark.parametrize(
    "run_group_id",
    [4, 99, 1233456],
)
@pytest.mark.asyncio
async def test_select_user_with_run_group_or_raise__raises_for_non_existent_run_group(
    run_group_id: int, pg_base_config
):
    with pytest.raises(HTTPException):
        async with generate_async_session(pg_base_config) as session:
            _ = await select_user_with_run_group_or_raise(session=session, run_group_id=run_group_id)


@pytest.mark.parametrize("run_id, user_id", [(1, 1), (5, 1), (6, 2), (8, 1)])
@pytest.mark.asyncio
async def test_select_user_with_run_or_raise(run_id: int, user_id: int, pg_base_config):
    async with generate_async_session(pg_base_config) as session:
        user = await select_user_with_run_or_raise(session=session, run_id=run_id)
        assert isinstance(user, User)
        assert user.user_id == user_id


@pytest.mark.parametrize(
    "run_id",
    [9, 72, 123456],
)
@pytest.mark.asyncio
async def test_select_user_with_run_or_raise__raise_for_non_existent_run(run_id: int, pg_base_config):
    with pytest.raises(HTTPException):
        async with generate_async_session(pg_base_config) as session:
            _ = await select_user_with_run_or_raise(session=session, run_id=run_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user_context, run_group_id, expected_user_context",
    [
        (
            UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
            1,
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # admin -> user 1
        (
            UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
            2,
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # admin -> user 1
        (
            UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
            3,
            UserContext(
                subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # admin -> user 2
        (
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
            1,
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # user 1 -> user 1 (can assume to be themselves)
        (
            UserContext(
                subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
            3,
            UserContext(
                subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # user 2 -> user 2 (can assume to be themselves)
    ],
)
async def test_assume_user_context_from_run_group(
    user_context: UserContext, run_group_id: int, expected_user_context: UserContext, pg_base_config
):

    async with generate_async_session(pg_base_config) as session:
        # Act
        assumed_user_context, previous_user_context = await assume_user_context_from_run_group(
            session=session, user_context=user_context, run_group_id=run_group_id
        )

        assert previous_user_context == user_context
        assert assumed_user_context == expected_user_context


@pytest.mark.asyncio
async def test_assume_user_context_from_run_group_raise_exception(pg_base_config):

    NONEXISTENT_RUN_GROUP_ID = 72

    async with generate_async_session(pg_base_config) as session:
        with pytest.raises(HTTPException):
            _ = await assume_user_context_from_run_group(
                session=session,
                user_context=UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
                run_group_id=NONEXISTENT_RUN_GROUP_ID,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user_context, run_id, expected_user_context",
    [
        (
            UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
            1,
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # admin -> user 1
        (
            UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
            5,
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # admin -> user 1
        (
            UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
            6,
            UserContext(
                subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # admin -> user 2
        (
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
            2,
            UserContext(
                subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # user 1 -> user 1 (can assume to be themselves)
        (
            UserContext(
                subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
            6,
            UserContext(
                subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
            ),
        ),  # user 2 -> user 2 (can assume to be themselves)
    ],
)
async def test_assume_user_context_from_run(
    user_context: UserContext, run_id: int, expected_user_context: UserContext, pg_base_config
):

    async with generate_async_session(pg_base_config) as session:
        # Act
        assumed_user_context, previous_user_context = await assume_user_context_from_run(
            session=session, user_context=user_context, run_id=run_id
        )

        assert previous_user_context == user_context
        assert assumed_user_context == expected_user_context


@pytest.mark.asyncio
async def test_assume_user_context_from_run_raise_exception(pg_base_config):

    NONEXISTENT_RUN_ID = 72

    async with generate_async_session(pg_base_config) as session:
        with pytest.raises(HTTPException):
            _ = await assume_user_context_from_run(
                session=session,
                user_context=UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all]),
                run_id=NONEXISTENT_RUN_ID,
            )
