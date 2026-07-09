from http import HTTPStatus

import pytest
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import UserConfigurationRequest, UserConfigurationResponse
from sqlalchemy import select

from cactus_orchestrator.model import User


@pytest.mark.parametrize(
    "user_vals, input_domain, input_pen, expected_domain, expected_pen",
    [
        (
            User(subscription_domain="", pen=0),
            "",
            0,
            "",
            0,
        ),
        (
            User(subscription_domain="my.domain.example", pen=64),
            None,
            None,
            "my.domain.example",
            64,
        ),
        (
            User(subscription_domain="my.domain.example", pen=64),
            "my.domain.example",
            64,
            "my.domain.example",
            64,
        ),
        (
            User(subscription_domain="foo", pen=64),
            "http://my.other.example:123/foo/bar",
            None,
            "my.other.example",
            64,
        ),
        (
            User(subscription_domain="foo", pen=64),
            None,
            64,
            "foo",
            64,
        ),  # Leave PEN unchanged
        (
            User(subscription_domain="foo", pen=64),
            None,
            108,
            "foo",
            108,
        ),  # Update PEN
        (
            User(subscription_domain="foo", pen=64),
            None,
            0,
            "foo",
            0,
        ),  # Reset PEN
    ],
)
async def test_update_existing_config(
    client,
    pg_base_config,
    valid_jwt_user1,
    user_vals: User,
    input_domain: str | None,
    input_pen: int,
    expected_domain: str,
    expected_pen: int,
):
    # Arrange
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = user_vals.subscription_domain
        user.pen = user_vals.pen
        await session.commit()

    # Act
    req = UserConfigurationRequest(
        subscription_domain=input_domain,
        pen=input_pen,
    )
    res = await client.post("/config", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, content=req.to_json())

    # Assert
    assert res.status_code == HTTPStatus.CREATED

    data: UserConfigurationResponse = UserConfigurationResponse.from_json(res.text)
    assert data.subscription_domain == expected_domain
    assert data.pen == expected_pen

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        if expected_domain == "":
            assert user.subscription_domain is None
        else:
            assert user.subscription_domain == expected_domain
