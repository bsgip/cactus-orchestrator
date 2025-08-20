from http import HTTPStatus

import pytest
from cactus_test_definitions import CSIPAusVersion, TestProcedureId

from cactus_orchestrator.schema import TestProcedureRunSummaryResponse


@pytest.mark.asyncio
async def test_get_version_list_populated(client, valid_jwt_user1):
    """Test when there are test procedure available."""

    # Act
    res = await client.get("/version", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()

    assert len(data["items"]) > 1, "Should be at least two or more entries"
    assert all([CSIPAusVersion(v["version"]).value == v["version"] for v in data["items"]]), "Version should match enum"


@pytest.mark.asyncio
async def test_get_test_procedure_list_populated(client, valid_jwt_user1):
    """Basic test that we can fetch test procedures."""

    # Act
    res = await client.get("/procedure", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = res.json()
    assert data["total"] > 1
    assert len(data["items"]) > 1
    assert data["items"][0]["test_procedure_id"] == "ALL-01"


@pytest.mark.parametrize(
    "run_id, status", [("ALL-01", 200), ("LOA-02", 200), ("GEN-03", 200), ("../ALL-01", 404), ("./ALL-01.yaml", 404)]
)
@pytest.mark.asyncio
async def test_get_test_procedures_by_id(client, valid_jwt_user1, run_id, status):
    """Test we can fetch individual test procedures by id"""

    # Act
    res = await client.get(f"/procedure/{run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == status
    if status == 200:
        res.headers["Content-Type"] == "application/yaml"
        assert len(res.text) > 10


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
            None,
        ),
        (99, None),
    ],
)
@pytest.mark.asyncio
async def test_procedure_run_summaries_for_group(
    client, pg_base_config, valid_jwt_user1, run_group_id, expected_id_counts
):
    """Test retrieving procedure run summaries"""

    # Act
    res = await client.get(f"/procedure_runs/{run_group_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    if expected_id_counts is None:
        assert res.status_code == HTTPStatus.FORBIDDEN
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
async def test_procedure_run_summaries_for_group_target_versions(client, pg_base_config, valid_jwt_user1):
    """Test retrieving procedure run summaries also doesn't serve summaries for tests outside the RunGroup's version
    target"""

    # RunGroup 1 is v1.2
    res = await client.get("/procedure_runs/1", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert res.status_code == HTTPStatus.OK
    v12_items = [TestProcedureRunSummaryResponse.model_validate(d) for d in res.json()]

    # RunGroup 2 is v1.3-beta-storage
    res = await client.get("/procedure_runs/2", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert res.status_code == HTTPStatus.OK
    v13_bess_items = [TestProcedureRunSummaryResponse.model_validate(d) for d in res.json()]

    # BES_01 is definitely in v1.3-storage extensions but NOT in v1.2
    assert TestProcedureId.BES_01 in [i.test_procedure_id for i in v13_bess_items]
    assert TestProcedureId.BES_01 not in [i.test_procedure_id for i in v12_items]


@pytest.mark.parametrize(
    "run_group_id, procedure, expected_run_ids",
    [
        (1, TestProcedureId.ALL_01, [2, 1]),
        (2, TestProcedureId.ALL_01, [5]),
        (1, TestProcedureId.ALL_02, [3]),
        (1, TestProcedureId.ALL_20, []),
        (3, TestProcedureId.ALL_01, None),
        (99, TestProcedureId.ALL_01, None),
    ],
)
@pytest.mark.asyncio
async def test_get_runs_for_procedure(
    client,
    pg_base_config,
    valid_jwt_user1,
    run_group_id: int,
    procedure: TestProcedureId,
    expected_run_ids: list[int] | None,
):
    """Test retrieving paginated user runs (underneath a procedure)"""

    # Act
    res = await client.get(
        f"/procedure_runs/{run_group_id}/{procedure.value}", headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    if expected_run_ids is None:
        assert res.status_code == HTTPStatus.FORBIDDEN
    else:
        assert res.status_code == HTTPStatus.OK
        data = res.json()
        assert isinstance(data, dict)
        assert "items" in data
        assert len(data["items"]) == len(expected_run_ids)
        assert expected_run_ids == [d["run_id"] for d in data["items"]]
