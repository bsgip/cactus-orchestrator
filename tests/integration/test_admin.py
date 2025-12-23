from http import HTTPStatus

import pytest
from assertical.fake.generator import generate_class_instance
from assertical.fixtures.postgres import generate_async_session
from cactus_runner.models import RunnerStatus
from cactus_schema.orchestrator import (
    HEADER_GROUP_ID,
    HEADER_GROUP_NAME,
    HEADER_RUN_ID,
    HEADER_TEST_ID,
    HEADER_USER_NAME,
    RunGroupResponse,
    RunResponse,
    TestProcedureRunSummaryResponse,
    UserWithRunGroupsResponse,
)
from cactus_test_definitions.client import TestProcedureId
from sqlalchemy import select

from cactus_orchestrator.main import generate_app
from cactus_orchestrator.model import RunArtifact
from cactus_orchestrator.settings import get_current_settings
from tests.integration import MockedK8s


@pytest.mark.asyncio
async def test_get_test_user_list_populated(pg_base_config, client, valid_jwt_admin1):
    """Basic test checking that we can fetch list of users."""
    # Act
    res = await client.get("/admin/users", headers={"Authorization": f"Bearer {valid_jwt_admin1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert len(data) == 3
    _ = [UserWithRunGroupsResponse.model_validate(d) for d in data]


@pytest.fixture(scope="session")
def admin_endpoints() -> list[str]:
    app = generate_app(get_current_settings())
    paths = []
    # The values of the path parameters don't matter.
    # We only need an properly constructed URL to test whether the route is authorised
    path_parameters = {"{run_group_id}": "1", "{run_id}": "1"}

    for route in app.routes:
        path = route.path
        if path.startswith("/admin"):
            for match, replacement in path_parameters.items():
                if match in path:
                    path = path.replace(match, replacement)
            paths.append(path)

    return paths


@pytest.mark.asyncio
async def test_get_admin_endpoint_not_authorised_for_nonadmin(admin_endpoints: list[str], client, valid_jwt_user1):
    """Verifies that jwt must have admin privileges to access admin endpoints"""

    for endpoint in admin_endpoints:
        # Act
        res = await client.get(endpoint, headers={"Authorization": f"Bearer {valid_jwt_user1}"})

        # Assert
        assert res.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.asyncio
async def test_admin_get_users(client, pg_base_config, valid_jwt_admin1):

    # Act
    res = await client.get(f"/admin/users", headers={"Authorization": f"Bearer {valid_jwt_admin1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, list)
    items = [UserWithRunGroupsResponse.model_validate(i) for i in data]

    assert len(data) == 3  # 3 users registered in pg_base_config
    run_group_count = [None, 2, 1, 0]
    for item in items:
        if item.name:
            assert item.name == f"user{item.user_id}@cactus.example.com"
        assert item.subject_id == f"user{item.user_id}"
        assert len(item.run_groups) == run_group_count[item.user_id]


@pytest.mark.parametrize(
    "run_group_id, expected_id_counts",
    [
        (
            1,
            [
                (TestProcedureId.ALL_01, 2),
                (TestProcedureId.ALL_02, 1),
                (TestProcedureId.ALL_03, 1),
                (TestProcedureId.ALL_04, 1),
                (TestProcedureId.ALL_05, 1),
            ],
        ),
        (
            2,
            [
                (TestProcedureId.ALL_01, 1),
            ],
        ),
        (
            3,
            [
                (TestProcedureId.GEN_02, 1),
            ],
        ),
        (99, None),
    ],
)
@pytest.mark.asyncio
async def test_admin_procedure_run_summaries_for_group(
    client, pg_base_config, valid_jwt_admin1, run_group_id, expected_id_counts
):
    """Test retrieving procedure run summaries"""

    # Act
    res = await client.get(
        f"/admin/procedure_runs/{run_group_id}", headers={"Authorization": f"Bearer {valid_jwt_admin1}"}
    )

    # Assert
    if expected_id_counts is None:
        assert res.status_code == HTTPStatus.NOT_FOUND
    else:
        assert res.status_code == HTTPStatus.OK
        data = res.json()
        assert isinstance(data, list)
        assert (
            len(data) > 10
        ), "Not every test is visible to every version (RunGroup) but there should be more tests than records in the DB"

        items = [TestProcedureRunSummaryResponse.model_validate(d) for d in data]
        counts_by_procedure_id = {procedure: count for procedure, count in expected_id_counts}

        assert all((i.category for i in items)), "Should not be empty"
        assert all((i.description for i in items)), "Should not be empty"

        for summary in items:
            assert summary.run_count == counts_by_procedure_id.get(summary.test_procedure_id, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("run_group_id, run_groups, run_counts", [(1, [1, 2], [6, 1]), (3, [3], [1])])
async def test_get_groups_paginated(
    run_group_id: int, run_groups: list[int], run_counts: list[int], client, pg_base_config, valid_jwt_admin1
):
    """Can run groups be fetched for a specific user"""

    # Act
    res = await client.get(
        f"/admin/run_group?run_group_id={run_group_id}", headers={"Authorization": f"Bearer {valid_jwt_admin1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, dict)
    assert "items" in data
    items = [RunGroupResponse.model_validate(i) for i in data["items"]]

    for i, item in enumerate(items):
        assert item.run_group_id == run_groups[i]
        assert item.total_runs == run_counts[i]


@pytest.mark.parametrize(
    "run_group_id, procedure, expected_run_ids",
    [
        (1, TestProcedureId.ALL_01, [2, 1]),
        (2, TestProcedureId.ALL_01, [5]),
        (1, TestProcedureId.ALL_02, [3]),
        (1, TestProcedureId.ALL_20, []),
        (3, TestProcedureId.GEN_02, [6]),
        (99, TestProcedureId.ALL_01, []),
    ],
)
@pytest.mark.asyncio
async def test_admin_get_runs_for_procedure_in_group(
    client,
    pg_base_config,
    valid_jwt_admin1,
    run_group_id: int,
    procedure: TestProcedureId,
    expected_run_ids: list[int],
):
    """Test retrieving paginated user runs (underneath a procedure)"""

    # Act
    res = await client.get(
        f"/admin/procedure_runs/{run_group_id}/{procedure.value}",
        headers={"Authorization": f"Bearer {valid_jwt_admin1}"},
    )

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert isinstance(data, dict)
    assert "items" in data
    assert len(data["items"]) == len(expected_run_ids)
    assert expected_run_ids == [d["run_id"] for d in data["items"]]


@pytest.mark.parametrize(
    "run_group_id, finalised, expected_run_ids",
    [(1, None, [8, 7, 4, 3, 2, 1]), (1, True, [7, 4, 3, 2]), (1, False, [8, 1]), (2, None, [5]), (3, None, [6])],
)
@pytest.mark.asyncio
async def test_admin_get_group_runs_paginated(
    client,
    pg_base_config,
    valid_jwt_admin1,
    run_group_id: int,
    finalised: bool | None,
    expected_run_ids: list[int] | None,
):
    """Test retrieving paginated user runs"""

    params = {}
    if finalised is not None:
        params["finalised"] = finalised

    # Act
    res = await client.get(
        f"/admin/run_group/{run_group_id}/run", params=params, headers={"Authorization": f"Bearer {valid_jwt_admin1}"}
    )

    # Assert
    if expected_run_ids is None:
        assert res.status_code == HTTPStatus.FORBIDDEN
    else:
        assert res.status_code == HTTPStatus.OK
        data = res.json()
        assert isinstance(data, dict)
        assert "items" in data
        assert expected_run_ids == [i["run_id"] for i in data["items"]]


@pytest.mark.parametrize(
    "run_id, expected_status",
    [
        (1, HTTPStatus.OK),
        (5, HTTPStatus.OK),
        (8, HTTPStatus.OK),
        (2, HTTPStatus.GONE),
        (6, HTTPStatus.OK),
        (9, HTTPStatus.NOT_FOUND),
        (99, HTTPStatus.NOT_FOUND),
    ],
)
async def test_admin_get_run_status(
    k8s_mock: MockedK8s, client, pg_base_config, valid_jwt_admin1, run_id, expected_status
):
    """Does fetching the run status work under success conditions"""

    # Act
    status_response_data = generate_class_instance(RunnerStatus, generate_relationships=True, step_status={})
    k8s_mock.status.return_value = status_response_data

    res = await client.get(f"/admin/run/{run_id}/status", headers={"Authorization": f"Bearer {valid_jwt_admin1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        actual_status = RunnerStatus.from_dict(res.json())
        assert actual_status == status_response_data
        k8s_mock.status.assert_called_once()
    else:
        k8s_mock.status.assert_not_called()


@pytest.mark.parametrize(
    "run_id, expected_status",
    [(1, HTTPStatus.OK), (7, HTTPStatus.OK), (5, HTTPStatus.OK), (6, HTTPStatus.OK), (99, HTTPStatus.NOT_FOUND)],
)
@pytest.mark.asyncio
async def test_admin_get_individual_run(client, pg_base_config, valid_jwt_admin1, run_id, expected_status):
    """Test fetching a single run by ID"""

    # Act
    res = await client.get(f"/admin/run/{run_id}", headers={"Authorization": f"Bearer {valid_jwt_admin1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        run_response = RunResponse.model_validate_json(res.text)
        assert run_response.run_id == run_id
        assert run_response.test_url


@pytest.mark.parametrize("run_group_id", [1, 2, 3])
@pytest.mark.asyncio
async def test_admin_get_procedure_run_summaries_for_group(client, pg_base_config, valid_jwt_admin1, run_group_id: int):

    # Act
    res = await client.get(
        f"/admin/procedure_runs/{run_group_id}", headers={"Authorization": f"Bearer {valid_jwt_admin1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.OK
    for run_summary in res.json():
        TestProcedureRunSummaryResponse.model_validate(run_summary)


@pytest.mark.parametrize(
    "run_id,expected_status,expected_artifact_id,expected_user,expected_test_id,expected_group_name,expected_group_id",
    [
        (1, HTTPStatus.NOT_FOUND, None, None, None, None, None),
        (5, HTTPStatus.OK, 3, "user1@cactus.example.com", "ALL-01", "name-2", "2"),
        (99, HTTPStatus.NOT_FOUND, None, None, None, None, None),  # DNE
    ],
)
async def test_get_run_artifact_data(
    k8s_mock: MockedK8s,
    client,
    pg_base_config,
    valid_jwt_admin1,
    run_id,
    expected_status,
    expected_artifact_id,
    expected_user,
    expected_test_id,
    expected_group_name,
    expected_group_id,
):
    """Does fetching the run artifact data work under common conditions"""

    # Arrange
    expected_artifact_data = None
    async with generate_async_session(pg_base_config) as session:
        artifact = (
            await session.execute(select(RunArtifact).where(RunArtifact.run_artifact_id == expected_artifact_id))
        ).scalar_one_or_none()
        if artifact:
            expected_artifact_data = artifact.file_data

    # Act
    res = await client.get(f"admin/run/{run_id}/artifact", headers={"Authorization": f"Bearer {valid_jwt_admin1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:

        assert expected_artifact_data == res.read()

        assert res.headers[HEADER_USER_NAME] == expected_user
        assert res.headers[HEADER_TEST_ID] == expected_test_id
        assert res.headers[HEADER_RUN_ID] == str(run_id)
        assert res.headers[HEADER_GROUP_ID] == expected_group_id
        assert res.headers[HEADER_GROUP_NAME] == expected_group_name
