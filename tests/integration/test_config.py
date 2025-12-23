import os
from http import HTTPStatus

import pytest
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import UserConfigurationRequest, UserConfigurationResponse
from sqlalchemy import select

from cactus_orchestrator.k8s.resource import generate_static_test_stack_id
from cactus_orchestrator.model import User


@pytest.mark.parametrize("is_static_uri", [True, False])
async def test_fetch_existing_config_domain_none_value(client, pg_base_config, valid_jwt_user2, is_static_uri: bool):
    # Arrange
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 2))).scalar_one()
        user.subscription_domain = None
        user.is_static_uri = is_static_uri

        expected_static_uri_component = generate_static_test_stack_id(user)
        await session.commit()

    # Act
    res = await client.get("/config", headers={"Authorization": f"Bearer {valid_jwt_user2}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = UserConfigurationResponse.from_json(res.text)
    assert data.subscription_domain == ""
    assert data.is_static_uri is is_static_uri
    if is_static_uri:
        assert expected_static_uri_component in data.static_uri
        assert os.environ["TEST_EXECUTION_FQDN"] in data.static_uri
        assert data.static_uri.endswith("/dcap")
    else:
        assert data.static_uri is None


@pytest.mark.parametrize(
    "user_vals, input_domain, input_is_static_uri, input_pen, expected_domain, expected_is_static_uri, expected_pen",  # noqa 501
    [
        (
            User(subscription_domain="", is_static_uri=False, pen=0),
            "",
            True,
            0,
            "",
            True,
            0,
        ),
        (
            User(subscription_domain="my.domain.example", is_static_uri=True, pen=64),
            "my.domain.example",
            None,
            None,
            "my.domain.example",
            True,
            64,
        ),
        (
            User(subscription_domain="my.domain.example", is_static_uri=True, pen=64),
            "my.domain.example",
            False,
            64,
            "my.domain.example",
            False,
            64,
        ),
        (
            User(subscription_domain="foo", is_static_uri=False, pen=64),
            "http://my.other.example:123/foo/bar",
            None,
            None,
            "my.other.example",
            False,
            64,
        ),
        (
            User(subscription_domain="foo", is_static_uri=True, pen=64),
            None,
            True,
            None,
            "foo",
            True,
            64,
        ),
        (
            User(subscription_domain="foo", is_static_uri=False, pen=64),
            None,
            True,
            None,
            "foo",
            True,
            64,
        ),
        (
            User(subscription_domain="foo", is_static_uri=False, pen=64),
            None,
            None,
            64,
            "foo",
            False,
            64,
        ),  # Leave PEN unchanged
        (
            User(subscription_domain="foo", is_static_uri=False, pen=64),
            None,
            None,
            108,
            "foo",
            False,
            108,
        ),  # Update PEN
        (
            User(subscription_domain="foo", is_static_uri=False, pen=64),
            None,
            None,
            0,
            "foo",
            False,
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
    input_is_static_uri: bool | None,
    input_pen: int,
    expected_domain: str,
    expected_is_static_uri: bool,
    expected_pen: int,
):
    # Arrange
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = user_vals.subscription_domain
        user.is_static_uri = user_vals.is_static_uri
        user.pen = user_vals.pen
        await session.commit()

    # Act
    req = UserConfigurationRequest(
        subscription_domain=input_domain,
        is_static_uri=input_is_static_uri,
        pen=input_pen,
    )
    res = await client.post("/config", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, content=req.to_json())

    # Assert
    assert res.status_code == HTTPStatus.CREATED

    data = UserConfigurationResponse.from_json(res.text)
    assert data.subscription_domain == expected_domain
    assert data.is_static_uri == expected_is_static_uri
    assert data.pen == expected_pen
    if expected_is_static_uri:
        assert os.environ["TEST_EXECUTION_FQDN"] in data.static_uri
        assert data.static_uri.endswith("/dcap")
    else:
        assert data.static_uri is None

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        if expected_domain == "":
            assert user.subscription_domain is None
        else:
            assert user.subscription_domain == expected_domain
        assert user.is_static_uri == expected_is_static_uri
