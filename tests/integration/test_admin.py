from http import HTTPStatus

import pytest
from assertical.fixtures.postgres import generate_async_session

from cactus_orchestrator.schema import UserWithRunGroupsResponse


@pytest.mark.asyncio
async def test_get_test_user_list_populated(pg_base_config, client, valid_jwt_admin1):
    """Basic test checking that we can fetch list of users."""

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
@pytest.mark.parametrize("endpoint", ["/admin/users"])
async def test_get_admin_endpoint_not_authorised_for_nonadmin(endpoint: str, client, valid_jwt_user1):
    """Verifies that jwt must have admin privileges to access admin endpoints"""

    # Act
    res = await client.get(endpoint, headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.asyncio
async def test_admin_get_procedure_run_summaries_for_group(pg_base_config, client, valid_jwt_admin1):
    """Basic test checking that we can fetch list of run groups for a user"""

    async with generate_async_session(pg_base_config) as session:
        await session.commit()

    run_group_id = 1
    # Act
    res = await client.get(
        f"/admin/procedure_runs/{run_group_id}", headers={"Authorization": f"Bearer {valid_jwt_admin1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert len(data) >= 66  # CSIP-Aus defines 66 tests.
    assert all(
        key in p
        for p in data
        for key in ["test_procedure_id", "description", "category", "classes", "run_count", "latest_all_criteria_met"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("run_group_id, run_group_count", [(1, 2), (2, 2), (3, 1)])
async def test_admin_get_groups_paginated(run_group_id, run_group_count, pg_base_config, client, valid_jwt_admin1):
    """Basic test checking that we can fetch list of run groups for a user"""

    async with generate_async_session(pg_base_config) as session:
        await session.commit()

    # Act
    res = await client.get(f"/admin/run_group/{run_group_id}", headers={"Authorization": f"Bearer {valid_jwt_admin1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert "total" in data
    assert len(data["items"]) == run_group_count
