import pytest
from assertical.fixtures.postgres import generate_async_session
from fastapi.exceptions import HTTPException

from cactus_orchestrator.api.admin import select_user_with_run_group_or_raise
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
