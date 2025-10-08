from fastapi.exceptions import HTTPException
import pytest
from assertical.fixtures.postgres import generate_async_session
from cactus_orchestrator.auth import AuthPerm, UserContext
from cactus_orchestrator.api.run import select_user_run_group_or_raise, select_user_with_run_group_or_raise
from cactus_orchestrator.model import User, RunGroup

admin_user_context = UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all, AuthPerm.user_all])
user_1_context = UserContext(
    subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
)
user_2_context = UserContext(
    subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
)


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


@pytest.mark.parametrize(
    "run_group_id, user_context, user_id",
    [
        (1, user_1_context, 1),  # user 1 run group 1
        (2, user_1_context, 1),  # user 1 run group 2
        (3, user_2_context, 2),  # user 2 run group 3
        # admin user request any run group
        (1, admin_user_context, 1),
        (2, admin_user_context, 1),
        (3, admin_user_context, 2),
    ],
)
@pytest.mark.asyncio
async def test_select_user_run_group_or_raise(
    run_group_id: int, user_context: UserContext, user_id: int, pg_base_config
):
    async with generate_async_session(pg_base_config) as session:
        user, run_group = await select_user_run_group_or_raise(
            session=session, user_context=user_context, run_group_id=run_group_id
        )
        assert isinstance(user, User)
        assert user.user_id == user_id
        assert isinstance(run_group, RunGroup)


@pytest.mark.parametrize(
    "run_group_id, user_context",
    [
        (3, user_1_context),  # user 1 can't access run_group 3
        (1, user_2_context),  # user 2 can't access run_group 1
        (4, admin_user_context),  # there is no run_group 4
    ],
)
@pytest.mark.asyncio
async def test_select_user_run_group_or_raise__raises_exception(
    run_group_id: int, user_context: UserContext, pg_base_config
):

    async with generate_async_session(pg_base_config) as session:
        with pytest.raises(HTTPException):
            _ = await select_user_run_group_or_raise(
                session=session, user_context=user_context, run_group_id=run_group_id
            )
