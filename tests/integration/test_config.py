import os
from http import HTTPStatus

import pytest
from assertical.fixtures.postgres import generate_async_session
from sqlalchemy import select

from cactus_orchestrator.k8s.resource import generate_static_test_stack_id
from cactus_orchestrator.model import User
from cactus_orchestrator.schema import UserConfigurationRequest, UserConfigurationResponse


@pytest.mark.parametrize("is_static_uri, is_device_cert", [(True, False), (False, True)])
@pytest.mark.asyncio
async def test_fetch_existing_config_no_certs(
    client, pg_base_config, valid_jwt_user1, is_static_uri: bool, is_device_cert: bool
):
    # Arrange
    domain = "my.custom.domain"
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = domain
        user.is_static_uri = is_static_uri
        user.is_device_cert = is_device_cert

        expected_static_uri_component = generate_static_test_stack_id(user)
        await session.commit()

    # Act
    res = await client.get("/config", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = UserConfigurationResponse.model_validate_json(res.content)
    assert data.subscription_domain == domain
    assert data.is_static_uri is is_static_uri
    assert data.is_device_cert is is_device_cert
    if is_static_uri:
        assert expected_static_uri_component in data.static_uri
        assert os.environ["TEST_EXECUTION_FQDN"] in data.static_uri
        assert data.static_uri.endswith("/dcap")
    else:
        assert data.static_uri is None
    assert data.aggregator_certificate_expiry is None
    assert data.device_certificate_expiry is None


@pytest.mark.parametrize("is_static_uri, is_device_cert", [(True, False), (False, True)])
async def test_fetch_existing_config_domain_none_value(
    client, pg_base_config, valid_jwt_user2, is_static_uri: bool, is_device_cert: bool
):
    # Arrange
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 2))).scalar_one()
        user.subscription_domain = None
        user.is_static_uri = is_static_uri
        user.is_device_cert = is_device_cert

        expected_static_uri_component = generate_static_test_stack_id(user)
        await session.commit()

    # Act
    res = await client.get("/config", headers={"Authorization": f"Bearer {valid_jwt_user2}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = UserConfigurationResponse.model_validate_json(res.content)
    assert data.subscription_domain == ""
    assert data.is_static_uri is is_static_uri
    assert data.is_device_cert is is_device_cert
    if is_static_uri:
        assert expected_static_uri_component in data.static_uri
        assert os.environ["TEST_EXECUTION_FQDN"] in data.static_uri
        assert data.static_uri.endswith("/dcap")
    else:
        assert data.static_uri is None
    assert data.aggregator_certificate_expiry is None
    assert data.device_certificate_expiry is None


@pytest.mark.parametrize(
    "user_vals, input_domain, input_is_static_uri, input_is_device_cert, expected_domain, expected_is_static_uri, expected_is_device_cert",
    [
        (User(subscription_domain="", is_static_uri=False, is_device_cert=True), "", True, False, "", True, False),
        (
            User(subscription_domain="my.domain.example", is_static_uri=True, is_device_cert=True),
            "my.domain.example",
            None,
            None,
            "my.domain.example",
            True,
            True,
        ),
        (
            User(subscription_domain="my.domain.example", is_static_uri=True, is_device_cert=True),
            "my.domain.example",
            False,
            False,
            "my.domain.example",
            False,
            False,
        ),
        (
            User(subscription_domain="foo", is_static_uri=False, is_device_cert=False),
            "http://my.other.example:123/foo/bar",
            None,
            None,
            "my.other.example",
            False,
            False,
        ),
        (
            User(subscription_domain="foo", is_static_uri=True, is_device_cert=False),
            None,
            True,
            False,
            "foo",
            True,
            False,
        ),
        (
            User(subscription_domain="foo", is_static_uri=False, is_device_cert=False),
            None,
            True,
            True,
            "foo",
            True,
            True,
        ),
    ],
)
async def test_update_existing_config(
    client,
    pg_base_config,
    valid_jwt_user1,
    user_vals: User,
    input_domain: str | None,
    input_is_static_uri: bool | None,
    input_is_device_cert: bool | None,
    expected_domain: str,
    expected_is_static_uri: bool,
    expected_is_device_cert: bool,
):
    # Arrange
    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = user_vals.subscription_domain
        user.is_static_uri = user_vals.is_static_uri
        user.is_device_cert = user_vals.is_device_cert
        await session.commit()

    # Act
    req = UserConfigurationRequest(
        subscription_domain=input_domain, is_static_uri=input_is_static_uri, is_device_cert=input_is_device_cert
    )
    res = await client.post("/config", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, json=req.model_dump())

    # Assert
    assert res.status_code == HTTPStatus.CREATED

    data = UserConfigurationResponse.model_validate_json(res.content)
    assert data.subscription_domain == expected_domain
    assert data.is_static_uri == expected_is_static_uri
    assert data.is_device_cert == expected_is_device_cert
    if expected_is_static_uri:
        assert os.environ["TEST_EXECUTION_FQDN"] in data.static_uri
        assert data.static_uri.endswith("/dcap")
    else:
        assert data.static_uri is None
    data.device_certificate_expiry = None
    data.aggregator_certificate_expiry = None

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        if expected_domain == "":
            assert user.subscription_domain is None
        else:
            assert user.subscription_domain == expected_domain
        assert user.is_static_uri == expected_is_static_uri
        assert user.is_device_cert == expected_is_device_cert
