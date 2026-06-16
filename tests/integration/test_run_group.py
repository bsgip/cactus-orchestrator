import os
from datetime import UTC, datetime
from http import HTTPStatus
from unittest.mock import AsyncMock, patch

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import RunGroupRequest, RunGroupResponse, RunGroupUpdateRequest
from cactus_test_definitions import CSIPAusVersion
from sqlalchemy import func, select

from cactus_orchestrator.model import Run, RunArtifact, RunGroup


@pytest.mark.asyncio
async def test_get_groups_paginated(client, pg_base_config, valid_jwt_user1):
    """Can run groups be fetched for a specific user"""

    # Act
    res = await client.get("/run_group", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, dict)
    assert "items" in data
    items = [RunGroupResponse.from_dict(i) for i in data["items"]]

    assert [1, 2] == [i.run_group_id for i in items]
    assert items[0].csip_aus_version == "v1.2"
    assert items[1].csip_aus_version == "v1.3-beta/storage"
    assert items[0].name == "name-1"
    assert items[1].name == "name-2"
    assert items[0].total_runs == 6
    assert items[1].total_runs == 1
    assert items[0].is_device_cert is True
    assert items[1].is_device_cert is None
    assert items[0].certificate_created_at == datetime(2023, 1, 1, 0, 1, 0, tzinfo=UTC)
    assert items[1].certificate_created_at is None
    assert items[0].certificate_id == 11
    assert items[1].certificate_id == 0


@pytest.mark.parametrize(
    "run_group_id, name, is_static_uri, expected_status, expected_name, expected_is_static_uri",
    [
        (1, "The updated name", True, HTTPStatus.OK, "The updated name", True),
        (1, "The updated name", False, HTTPStatus.OK, "The updated name", False),
        (1, None, False, HTTPStatus.OK, "name-1", False),
        (1, "", True, HTTPStatus.OK, "name-1", True),
        (2, "New-Name#?%$}{[]}", False, HTTPStatus.OK, "New-Name#?%$}{[]}", False),
        (3, "Wrong User", True, HTTPStatus.FORBIDDEN, "name-3", False),
    ],
)
@pytest.mark.asyncio
async def test_update_group(
    client,
    pg_base_config,
    valid_jwt_user1,
    run_group_id,
    name,
    is_static_uri,
    expected_status,
    expected_name,
    expected_is_static_uri,
):
    """Can groups be updated for a specific user"""

    # Act
    body = RunGroupUpdateRequest(name=name, is_static_uri=is_static_uri)
    response = await client.put(
        f"/run_group/{run_group_id}",
        headers={"Authorization": f"Bearer {valid_jwt_user1}"},
        content=body.to_json(),
    )

    # Assert
    assert response.status_code == expected_status
    async with generate_async_session(pg_base_config) as session:
        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        assert run_group.name == expected_name
        assert run_group.is_static_uri is expected_is_static_uri

    if expected_status == HTTPStatus.OK:
        response_data: RunGroupResponse = RunGroupResponse.from_json(response.text)
        assert not isinstance(response_data, list)
        assert response_data.run_group_id == run_group_id
        assert response_data.name == expected_name
        assert response_data.is_static_uri is expected_is_static_uri
        if expected_is_static_uri:
            assert (
                response_data.static_uri is not None and os.environ["TEST_EXECUTION_FQDN"] in response_data.static_uri
            )
        else:
            assert response_data.static_uri is None


@pytest.mark.parametrize(
    "version, is_static_uri, expected_status",
    [
        (CSIPAusVersion.RELEASE_1_2.value, True, HTTPStatus.CREATED),
        (CSIPAusVersion.RELEASE_1_2.value, False, HTTPStatus.CREATED),
        (CSIPAusVersion.BETA_1_3_STORAGE.value, True, HTTPStatus.CREATED),
        (CSIPAusVersion.BETA_1_3_STORAGE.value, False, HTTPStatus.CREATED),
        ("v99.88", True, HTTPStatus.BAD_REQUEST),
    ],
)
@pytest.mark.asyncio
async def test_create_group(client, pg_base_config, valid_jwt_user1, version, is_static_uri, expected_status):
    """Can run groups be created for a specific user"""

    # Act

    body = RunGroupRequest(csip_aus_version=version, is_static_uri=is_static_uri)

    response = await client.post(
        "/run_group", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, content=body.to_json()
    )

    # Assert
    assert response.status_code == expected_status
    if expected_status == HTTPStatus.CREATED:
        result: RunGroupResponse = RunGroupResponse.from_json(response.text)
        assert result.name, "Should be set to something"
        assert result.run_group_id > 0
        assert result.csip_aus_version == version
        assert result.is_static_uri is is_static_uri
        assert_nowish(result.created_at)

        async with generate_async_session(pg_base_config) as session:
            run_group = (
                await session.execute(select(RunGroup).where(RunGroup.run_group_id == result.run_group_id))
            ).scalar_one()

            assert run_group.name == result.name
            assert run_group.csip_aus_version == result.csip_aus_version
            assert run_group.created_at == result.created_at
            assert run_group.is_static_uri == result.is_static_uri
    else:
        async with generate_async_session(pg_base_config) as session:
            run_group_count = (await session.execute(select(func.count()).select_from(RunGroup))).scalar_one()
            assert run_group_count == 3, "Nothing should be created"


@pytest.mark.parametrize(
    "run_group_id, expected_status, expected_run_ids, expected_teardown_run_ids, expected_run_artifact_ids",
    [
        (1, HTTPStatus.NO_CONTENT, [1, 2, 3, 4, 7, 8], [1, 8], [1, 2]),
        (2, HTTPStatus.NO_CONTENT, [5], [5], [3]),
        (3, HTTPStatus.FORBIDDEN, [], [], []),
        (99, HTTPStatus.FORBIDDEN, [], [], []),
    ],
)
@patch("cactus_orchestrator.api.run_group.destroy_pod_resources", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_delete_group(
    mock_destroy_pod_resources: AsyncMock,
    client,
    pg_base_config,
    valid_jwt_user1,
    run_group_id: int,
    expected_status: HTTPStatus,
    expected_run_ids: list[int],
    expected_teardown_run_ids: list[int],
    expected_run_artifact_ids: list[int],
):
    """Can run groups be deleted for a specific user"""

    # Act
    async with generate_async_session(pg_base_config) as session:
        before_run_group_count = (await session.execute(select(func.count()).select_from(RunGroup))).scalar_one()
        before_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()
        before_artifact_count = (await session.execute(select(func.count()).select_from(RunArtifact))).scalar_one()

    response = await client.delete(f"/run_group/{run_group_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert response.status_code == expected_status
    async with generate_async_session(pg_base_config) as session:
        after_run_group_count = (await session.execute(select(func.count()).select_from(RunGroup))).scalar_one()
        after_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()
        after_artifact_count = (await session.execute(select(func.count()).select_from(RunArtifact))).scalar_one()
        remaining_run_ids = (
            (await session.execute(select(Run.run_id).where(Run.run_id.in_(expected_run_ids)))).scalars().all()
        )
        remaining_artifact_ids = (
            (
                await session.execute(
                    select(RunArtifact.run_artifact_id).where(
                        RunArtifact.run_artifact_id.in_(expected_run_artifact_ids)
                    )
                )
            )
            .scalars()
            .all()
        )

    if expected_status >= 200 and expected_status < 300:
        assert after_run_count == before_run_count - len(expected_run_ids)
        assert after_run_group_count == before_run_group_count - 1
        assert after_artifact_count == before_artifact_count - len(expected_run_artifact_ids)
        assert remaining_run_ids == []
        assert remaining_artifact_ids == []

        # Ensure any active runs are properly deallocated
        assert mock_destroy_pod_resources.await_count == len(expected_teardown_run_ids)

    else:
        assert after_run_count == before_run_count
        assert after_run_group_count == after_run_group_count
        assert remaining_run_ids == expected_run_ids
        assert remaining_artifact_ids == expected_run_artifact_ids

        mock_destroy_pod_resources.assert_not_awaited()
