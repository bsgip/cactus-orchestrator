from http import HTTPStatus
from unittest.mock import patch

import pytest
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import UserUpdateRequest
from sqlalchemy import select

from cactus_orchestrator.model import AuditChangeType, User
from tests.utils.audit import assert_audit_logs


@pytest.mark.asyncio
async def test_update_user_name(client, pg_base_config, valid_jwt_user1):
    """Basic test that we can fetch list of users."""

    new_user_name = "Fred"
    req = UserUpdateRequest(user_name=new_user_name)

    # Act
    res = await client.patch("/user", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, content=req.to_json())

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()

        # Assert
        assert res.status_code == HTTPStatus.OK
        assert user is not None
        assert user.user_name == new_user_name

    await assert_audit_logs(pg_base_config, [(1, AuditChangeType.USER_UPDATED, [1])])


@pytest.mark.asyncio
async def test_update_user_name_failure(client, pg_base_config, valid_jwt_user1, caplog):
    """Failures should be logged but not audited"""
    req = UserUpdateRequest(user_name="Fred")

    with patch("cactus_orchestrator.api.user.update_user_name", side_effect=Exception("mock failure")):
        res = await client.patch("/user", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, content=req.to_json())

    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert "mock failure" in caplog.text
    await assert_audit_logs(pg_base_config, [])
