import os
from datetime import datetime, timedelta, timezone
from http import HTTPMethod, HTTPStatus
from itertools import product
from unittest.mock import Mock

import pytest
from aiohttp import ClientConnectorDNSError
from assertical.asserts.time import assert_nowish
from assertical.fake.generator import generate_class_instance
from assertical.fixtures.postgres import generate_async_session
from cactus_runner.client import RunnerClientException
from cactus_runner.models import (
    CriteriaEntry,
    InitResponseBody,
    RequestData,
    RequestEntry,
    RequestList,
    RunnerStatus,
    StepStatus,
)
from cactus_test_definitions import CSIPAusVersion
from cactus_test_definitions.client import TestProcedureId
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import func, select, update
from sqlalchemy.orm import selectinload

from cactus_orchestrator.api.run import finalise_run, is_all_criteria_met
from cactus_orchestrator.k8s.resource import generate_static_test_stack_id
from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User
from cactus_orchestrator.schema import (
    InitRunRequest,
    InitRunResponse,
    RunGroupRequest,
    RunGroupResponse,
    RunGroupUpdateRequest,
    RunResponse,
    StartRunResponse,
)
from tests.integration import MockedK8s


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
    items = [RunGroupResponse.model_validate(i) for i in data["items"]]

    assert [1, 2] == [i.run_group_id for i in items]
    assert items[0].csip_aus_version == "v1.2"
    assert items[1].csip_aus_version == "v1.3-beta/storage"
    assert items[0].name == "name-1"
    assert items[1].name == "name-2"
    assert items[0].total_runs == 6
    assert items[1].total_runs == 1
    assert items[0].is_device_cert is True
    assert items[1].is_device_cert is None
    assert items[0].certificate_created_at == datetime(2023, 1, 1, 0, 1, 0, tzinfo=timezone.utc)
    assert items[1].certificate_created_at is None
    assert items[0].certificate_id == 11
    assert items[1].certificate_id == 0


@pytest.mark.parametrize(
    "run_group_id, name, expected_status, expected_name",
    [
        (1, "The updated name", HTTPStatus.OK, "The updated name"),
        (1, None, HTTPStatus.OK, "name-1"),
        (1, "", HTTPStatus.OK, "name-1"),
        (2, "New-Name#?%$}{[]}", HTTPStatus.OK, "New-Name#?%$}{[]}"),
        (3, "Wrong User", HTTPStatus.FORBIDDEN, "name-3"),
    ],
)
@pytest.mark.asyncio
async def test_update_group(
    client, pg_base_config, valid_jwt_user1, run_group_id, name, expected_status, expected_name
):
    """Can groups be updated for a specific user"""

    # Act
    body = RunGroupUpdateRequest(name=name)
    response = await client.put(
        f"/run_group/{run_group_id}",
        headers={"Authorization": f"Bearer {valid_jwt_user1}"},
        content=body.model_dump_json(),
    )

    # Assert
    assert response.status_code == expected_status
    async with generate_async_session(pg_base_config) as session:
        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        assert run_group.name == expected_name

    if expected_status == HTTPStatus.OK:
        response_data = RunGroupResponse.model_validate_json(response.text)
        assert response_data.run_group_id == run_group_id
        assert response_data.name == expected_name


@pytest.mark.parametrize(
    "version, expected_status",
    [
        (CSIPAusVersion.RELEASE_1_2.value, HTTPStatus.CREATED),
        (CSIPAusVersion.BETA_1_3_STORAGE.value, HTTPStatus.CREATED),
        ("v99.88", HTTPStatus.BAD_REQUEST),
    ],
)
@pytest.mark.asyncio
async def test_create_group(client, pg_base_config, valid_jwt_user1, version, expected_status):
    """Can run groups be created for a specific user"""

    # Act

    body = RunGroupRequest(csip_aus_version=version)

    response = await client.post(
        "/run_group", headers={"Authorization": f"Bearer {valid_jwt_user1}"}, content=body.model_dump_json()
    )

    # Assert
    assert response.status_code == expected_status
    if expected_status == HTTPStatus.CREATED:
        result = RunGroupResponse.model_validate_json(response.text)
        assert result.name, "Should be set to something"
        assert result.run_group_id > 0
        assert result.csip_aus_version == version
        assert_nowish(result.created_at)

        async with generate_async_session(pg_base_config) as session:
            run_group = (
                await session.execute(select(RunGroup).where(RunGroup.run_group_id == result.run_group_id))
            ).scalar_one()

            assert run_group.name == result.name
            assert run_group.csip_aus_version == result.csip_aus_version
            assert run_group.created_at == result.created_at
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
@pytest.mark.asyncio
async def test_delete_group(
    client,
    pg_base_config,
    valid_jwt_user1,
    k8s_mock: MockedK8s,
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
        assert k8s_mock.delete_service.call_count == len(expected_teardown_run_ids)
        assert k8s_mock.delete_statefulset.call_count == len(expected_teardown_run_ids)
        assert k8s_mock.remove_ingress_rule.call_count == len(expected_teardown_run_ids)

    else:
        assert after_run_count == before_run_count
        assert after_run_group_count == after_run_group_count
        assert remaining_run_ids == expected_run_ids
        assert remaining_artifact_ids == expected_run_artifact_ids

        k8s_mock.delete_service.assert_not_called()
        k8s_mock.delete_statefulset.assert_not_called()
        k8s_mock.remove_ingress_rule.assert_not_called()
