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

        expected_static_uri = generate_static_test_stack_id(user)
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
        assert data.static_uri == generate_envoy_dcap_uri(expected_static_uri)
    else:
        assert data.static_uri is None
    assert data.aggregator_certificate_expiry is None
    assert data.device_certificate_expiry is None
