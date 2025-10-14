from http import HTTPStatus

import pytest
from assertical.fixtures.postgres import generate_async_session

from cactus_orchestrator.schema import UserWithRunGroupsResponse


@pytest.mark.asyncio
async def test_get_test_user_list_populated(pg_base_config, client, valid_jwt_admin1):
    """Basic test that we can fetch list of users."""

    async with generate_async_session(pg_base_config) as session:
        await session.commit()

    # Act
    res = await client.get("/admin/users", headers={"Authorization": f"Bearer {valid_jwt_admin1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    items = [UserWithRunGroupsResponse.model_validate(d) for d in data["items"]]
    assert items[0] == UserWithRunGroupsResponse(**{"user_id": 1, "name": "user1", "run_groups": [1, 2]})


@pytest.mark.asyncio
async def test_get_test_user_list_not_authorised(client, valid_jwt_user1):
    """Verifies that jwt must have admin privileges to access /users admin endpoint"""

    # Act
    res = await client.get("/admin/users", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.UNAUTHORIZED
