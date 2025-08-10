import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPMethod, HTTPStatus
from itertools import product
from typing import Generator
from unittest.mock import AsyncMock, Mock, call, patch

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fake.generator import generate_class_instance
from assertical.fake.sqlalchemy import assert_mock_session, create_mock_session
from assertical.fixtures.postgres import generate_async_session
from cactus_runner.client import RunnerClientException
from cactus_runner.models import CriteriaEntry, RequestEntry, RunnerStatus
from cactus_test_definitions import CSIPAusVersion, TestProcedureId
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi_pagination import Params, set_params
from sqlalchemy import select, update
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import undefer

from cactus_orchestrator.api.certificate import CertificateRouteType, _ca_crt_cachekey, update_ca_certificate_cache
from cactus_orchestrator.api.run import ensure_certificate_valid, finalise_run, is_all_criteria_met, teardown_teststack
from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.crud import ProcedureRunAggregated
from cactus_orchestrator.k8s.resource import generate_envoy_dcap_uri, generate_static_test_stack_id
from cactus_orchestrator.main import app
from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User
from cactus_orchestrator.schema import (
    InitRunRequest,
    InitRunResponse,
    RunResponse,
    StartRunResponse,
    TestProcedureResponse,
    TestProcedureRunSummaryResponse,
    UserConfigurationRequest,
    UserConfigurationResponse,
)
from cactus_orchestrator.settings import CactusOrchestratorException


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
        assert len(data) == len(TestProcedureId), "Aggregation for each test procedure"

        items = [TestProcedureRunSummaryResponse.model_validate(d) for d in data]
        counts_by_procedure_id = {procedure: count for procedure, count in expected_id_counts}

        assert all((i.category for i in items)), "Should not be empty"
        assert all((i.description for i in items)), "Should not be empty"

        for summary in items:
            assert summary.run_count == counts_by_procedure_id.get(summary.test_procedure_id, 0)


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
