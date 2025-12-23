from http import HTTPStatus

import pytest
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import UserUpdateRequest
from sqlalchemy import select

from cactus_orchestrator.model import User


@pytest.mark.asyncio
async def test_update_user_name(client, pg_base_config, valid_jwt_user1):
    """Basic test that we can fetch list of users."""

    new_user_name = "Fred"
    req = UserUpdateRequest(user_name=new_user_name)

    # Act
    res = await client.patch("/user", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, json=req.model_dump())

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()

        # Assert
        assert res.status_code == HTTPStatus.OK
        assert user is not None
        assert user.user_name == new_user_name
