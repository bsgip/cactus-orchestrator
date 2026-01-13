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
from cactus_schema.orchestrator import (
    HEADER_GROUP_ID,
    HEADER_GROUP_NAME,
    HEADER_RUN_ID,
    HEADER_TEST_ID,
    HEADER_USER_NAME,
    InitRunRequest,
    InitRunResponse,
    RunResponse,
    StartRunResponse,
)
from cactus_schema.runner import (
    CriteriaEntry,
    InitResponseBody,
    RequestData,
    RequestEntry,
    RequestList,
    RunnerStatus,
    RunRequest,
    StepStatus,
)
from cactus_test_definitions.client import TestProcedureId
from sqlalchemy import func, select, update
from sqlalchemy.orm import selectinload

from cactus_orchestrator.api.run import finalise_run, is_all_criteria_met
from cactus_orchestrator.k8s.resource import generate_static_test_stack_id
from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User
from tests.integration import MockedK8s


@pytest.mark.parametrize(
    "is_device_cert, run_group_id, expected_version",
    [
        (True, 1, "v1.2"),
        (False, 1, "v1.2"),
        (True, 2, "v1.3-beta/storage"),
        (False, 2, "v1.3-beta/storage"),
    ],
)
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_dynamic_uris(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
    is_device_cert: bool,
    run_group_id: int,
    expected_version: str,
):
    """Just a simple test of starting a run with all k8s functions stubbed under various circumstances"""

    subscription_domain = "abc.def"

    k8s_mock.health.return_value = True

    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain
        user.is_static_uri = False

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = is_device_cert

        expected_static_uri = generate_static_test_stack_id(user)

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model = InitRunResponse.from_json(res.text)
    assert os.environ["TEST_EXECUTION_FQDN"] in response_model.test_url, "The returned URI should be public facing"
    assert res.headers["Location"] == f"/run/{response_model.run_id}"

    # Check the k8s services were provisioned
    k8s_mock.clone_statefulset.assert_called_once()
    k8s_mock.clone_service.assert_called_once()
    k8s_mock.add_ingress_rule.assert_called_once()
    k8s_mock.wait_for_pod.assert_called_once()

    # Check init was called the correct params (a list of RunRequests)
    k8s_mock.init.assert_awaited_once()
    run_requests = k8s_mock.init.call_args_list[0].kwargs["run_request"]
    assert isinstance(run_requests, list)
    assert len(run_requests) == 1
    run_request = run_requests[0]
    assert isinstance(run_request, RunRequest)
    assert run_request.test_definition.test_procedure_id == TestProcedureId.ALL_01
    if is_device_cert:
        assert run_request.run_group.test_certificates.aggregator is None
        assert run_request.run_group.test_certificates.device == client_cert_pem_bytes.decode()
    else:
        assert run_request.run_group.test_certificates.device is None
        assert run_request.run_group.test_certificates.aggregator == client_cert_pem_bytes.decode()
    assert run_request.test_config.subscription_domain == subscription_domain
    assert run_request.run_id == str(response_model.run_id)
    assert run_request.run_group.csip_aus_version == expected_version

    # Check the DB
    async with generate_async_session(pg_base_config) as session:
        new_run = (await session.execute(select(Run).where(Run.run_id == response_model.run_id))).scalar_one()
        assert new_run.run_group_id == run_group_id
        assert new_run.run_status == RunStatus.initialised
        assert new_run.finalised_at is None
        assert new_run.teststack_id in response_model.test_url
        assert_nowish(new_run.created_at)
        assert new_run.teststack_id != expected_static_uri


@pytest.mark.parametrize("is_device_cert, is_started_response", product([True, False], [True, False]))
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_static_uri(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
    is_device_cert: bool,
    is_started_response: bool,
):
    """Just a simple test of starting a run with all k8s functions stubbed when URIs are requested to be static"""

    # The cert we WONT be using will be expired to ensure it doesn't block us

    subscription_domain = "abc.def"
    run_group_id = 1
    expected_version = "v1.2"

    k8s_mock.health.return_value = True

    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=is_started_response)

    async with generate_async_session(pg_base_config) as session:
        # Firstly ensure all user runs are expired before we start
        await session.execute(update(Run).values(run_status=RunStatus.terminated).where(Run.run_group_id.in_([1, 2])))

        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain
        user.is_static_uri = True
        expected_static_uri = generate_static_test_stack_id(user)

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = is_device_cert

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model = InitRunResponse.from_json(res.text)
    assert os.environ["TEST_EXECUTION_FQDN"] in response_model.test_url, "The returned URI should be public facing"
    assert res.headers["Location"] == f"/run/{response_model.run_id}"

    # Check the k8s services were provisioned
    k8s_mock.clone_statefulset.assert_called_once()
    k8s_mock.clone_service.assert_called_once()
    k8s_mock.add_ingress_rule.assert_called_once()
    k8s_mock.wait_for_pod.assert_called_once()

    # Check init was called the correct params (a list of RunRequests)
    k8s_mock.init.assert_awaited_once()
    run_requests = k8s_mock.init.call_args_list[0].kwargs["run_request"]
    assert isinstance(run_requests, list)
    assert len(run_requests) == 1
    run_request = run_requests[0]
    assert isinstance(run_request, RunRequest)
    assert run_request.test_definition.test_procedure_id == TestProcedureId.ALL_01
    if is_device_cert:
        assert run_request.run_group.test_certificates.aggregator is None
        assert run_request.run_group.test_certificates.device == client_cert_pem_bytes.decode()
    else:
        assert run_request.run_group.test_certificates.device is None
        assert run_request.run_group.test_certificates.aggregator == client_cert_pem_bytes.decode()
    assert run_request.test_config.subscription_domain == subscription_domain
    assert run_request.run_id == str(response_model.run_id)
    assert run_request.run_group.csip_aus_version == expected_version

    # Check the DB
    async with generate_async_session(pg_base_config) as session:
        new_run = (await session.execute(select(Run).where(Run.run_id == response_model.run_id))).scalar_one()
        assert new_run.run_group_id == run_group_id

        if is_started_response:
            assert new_run.run_status == RunStatus.started
        else:
            assert new_run.run_status == RunStatus.initialised
        assert new_run.finalised_at is None
        assert new_run.teststack_id in response_model.test_url
        assert_nowish(new_run.created_at)
        assert new_run.teststack_id == expected_static_uri


@pytest.mark.asyncio
async def test_spawn_teststack_and_init_tolerant_to_status_errors(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
):
    """The status will return failure a couple of times (as seen in real world testing) - the server should tolerate
    a small number of failures if the status eventually becomes good"""

    # The cert we WONT be using will be expired to ensure it doesn't block us
    subscription_domain = "abc.def"
    run_group_id = 1

    k8s_mock.health.side_effect = [ClientConnectorDNSError("mock 1", Mock()), False, True]

    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain
        user.is_static_uri = False

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model = InitRunResponse.from_json(res.text)
    assert os.environ["TEST_EXECUTION_FQDN"] in response_model.test_url, "The returned URI should be public facing"
    assert res.headers["Location"] == f"/run/{response_model.run_id}"

    # Check the k8s services were provisioned
    k8s_mock.clone_statefulset.assert_called_once()
    k8s_mock.clone_service.assert_called_once()
    k8s_mock.add_ingress_rule.assert_called_once()
    k8s_mock.wait_for_pod.assert_called_once()

    # Check init/status were called
    k8s_mock.init.assert_awaited_once()
    k8s_mock.health.call_count == 3

    # Check the DB
    async with generate_async_session(pg_base_config) as session:
        new_run = (await session.execute(select(Run).where(Run.run_id == response_model.run_id))).scalar_one()
        assert new_run.run_group_id == run_group_id
        assert new_run.run_status == RunStatus.initialised
        assert_nowish(new_run.created_at)


@pytest.mark.asyncio
async def test_spawn_teststack_and_init_too_many_status_errors(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
):
    """If the status check during init is constantly failing - ensure that the init is aborted and the test stack
    is torn down"""

    # The cert we WONT be using will be expired to ensure it doesn't block us
    subscription_domain = "abc.def"
    run_group_id = 1

    k8s_mock.health.side_effect = False
    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain
        user.is_static_uri = False

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run",
        content=req.to_json(),
        headers={"Authorization": f"Bearer {valid_jwt_user1}"},
        timeout=timedelta(seconds=30),
    )

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

    # Check the k8s services were provisioned - and then torn down
    k8s_mock.clone_statefulset.assert_called_once()
    k8s_mock.clone_service.assert_called_once()
    k8s_mock.wait_for_pod.assert_called_once()

    k8s_mock.delete_service.assert_called_once()
    k8s_mock.delete_statefulset.assert_called_once()
    k8s_mock.remove_ingress_rule.assert_called_once()

    # Check init/status were called
    assert k8s_mock.health.call_count > 0
    k8s_mock.init.assert_not_called()


@pytest.mark.parametrize(
    "is_device_cert",
    [True, False],
)
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_static_uri_collision(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
    is_device_cert: bool,
):
    """Starting a static URI run should fail if there is an existing run for the user"""

    subscription_domain = "abc.def"
    run_group_id = 1

    k8s_mock.health.return_value = True
    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain
        user.is_static_uri = True

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = is_device_cert

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CONFLICT

    # Check the k8s services were NOT provisioned
    k8s_mock.clone_statefulset.assert_not_called()
    k8s_mock.clone_service.assert_not_called()
    k8s_mock.add_ingress_rule.assert_not_called()
    k8s_mock.wait_for_pod.assert_not_called()


@pytest.mark.parametrize("run_group_id", [3, 99])
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_bad_run_group_id(
    client,
    k8s_mock: MockedK8s,
    valid_jwt_user1,
    run_group_id: int,
):
    """Can't start a run for a run group outside user's scope"""

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.FORBIDDEN

    # Check the k8s services were NOT provisioned
    k8s_mock.clone_statefulset.assert_not_called()
    k8s_mock.clone_service.assert_not_called()
    k8s_mock.add_ingress_rule.assert_not_called()
    k8s_mock.wait_for_pod.assert_not_called()


@pytest.mark.parametrize(
    "is_device_cert",
    [True, False],
)
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_expired_certs(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_expired_pem_bytes,
    valid_jwt_user1,
    is_device_cert: bool,
):
    """Can't start a run for a run group outside user's scope"""

    run_group_id = 1

    # Arrange
    async with generate_async_session(pg_base_config) as session:
        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_expired_pem_bytes
        run_group.is_device_cert = is_device_cert
        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.EXPECTATION_FAILED

    # Check the k8s services were NOT provisioned
    k8s_mock.clone_statefulset.assert_not_called()
    k8s_mock.clone_service.assert_not_called()
    k8s_mock.add_ingress_rule.assert_not_called()
    k8s_mock.wait_for_pod.assert_not_called()


@pytest.mark.parametrize(
    "is_device_cert",
    [True, False],
)
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_teardown_on_init_failure(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
    is_device_cert: bool,
):
    """k8s resources should be deallocated if a failure happens during init"""

    # The cert we WONT be using will be expired to ensure it doesn't block us
    run_group_id = 1

    # Arrange
    async with generate_async_session(pg_base_config) as session:
        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = is_device_cert

        await session.commit()

    k8s_mock.init.side_effect = RunnerClientException("My mock exception")

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

    # Check the k8s services were provisioned AND removed
    k8s_mock.clone_statefulset.assert_called_once()
    k8s_mock.clone_service.assert_called_once()
    k8s_mock.wait_for_pod.assert_called_once()
    k8s_mock.delete_service.assert_called_once()
    k8s_mock.delete_statefulset.assert_called_once()
    k8s_mock.remove_ingress_rule.assert_called_once()

    # Check init was called the correct params
    k8s_mock.init.assert_called_once()


@pytest.mark.parametrize("run_id, expected_success", [(6, True), (1, False), (99, False)])
@pytest.mark.asyncio
async def test_start_run(
    client, k8s_mock: MockedK8s, pg_base_config, valid_jwt_user2, run_id: int, expected_success: bool
):
    """Can a user start runs that are visible to them?"""

    # Act
    res = await client.post(f"/run/{run_id}", headers={"Authorization": f"Bearer {valid_jwt_user2}"})

    # Assert
    if expected_success:
        assert res.status_code == HTTPStatus.OK
        response_model = StartRunResponse.from_json(res.text)
        assert os.environ["TEST_EXECUTION_FQDN"] in response_model.test_url, "The returned URI should be public facing"

        k8s_mock.start.assert_called_once()

        async with generate_async_session(pg_base_config) as session:
            new_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one()
            assert new_run.run_status == RunStatus.started
    else:
        assert res.status_code == HTTPStatus.NOT_FOUND

        k8s_mock.start.assert_not_called()

        async with generate_async_session(pg_base_config) as session:
            new_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one_or_none()
            if new_run is not None:
                assert new_run.run_status == RunStatus.initialised


@pytest.mark.asyncio
async def test_start_run_precondition_failed(client, k8s_mock: MockedK8s, pg_base_config, valid_jwt_user1):
    """Will a precondition failed error from the runner proxy the right info to the client"""

    # Arrange
    error_message = "my mock error message"
    k8s_mock.start.side_effect = RunnerClientException(
        "Some sort of error", http_status_code=HTTPStatus.PRECONDITION_FAILED, error_message=error_message
    )
    run_id = 1

    # Act
    response = await client.post(f"/run/{run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert response.status_code == HTTPStatus.PRECONDITION_FAILED
    data = response.json()
    assert data["detail"] == error_message, "The error message we want to communicate is sent via the detail prop"


@pytest.mark.parametrize(
    "run_group_id, finalised, expected_run_ids",
    [(1, None, [8, 7, 4, 3, 2, 1]), (1, True, [7, 4, 3, 2]), (1, False, [8, 1]), (2, None, [5]), (3, None, None)],
)
@pytest.mark.asyncio
async def test_get_group_runs_paginated(
    client,
    pg_base_config,
    valid_jwt_user1,
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
        f"/run_group/{run_group_id}/run", params=params, headers={"Authorization": f"Bearer {valid_jwt_user1}"}
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
    [(1, HTTPStatus.OK), (7, HTTPStatus.OK), (5, HTTPStatus.OK), (6, HTTPStatus.NOT_FOUND), (99, HTTPStatus.NOT_FOUND)],
)
@pytest.mark.asyncio
async def test_get_individual_run(client, pg_base_config, valid_jwt_user1, run_id, expected_status):
    """Test fetching a single run by ID"""

    # Act
    res = await client.get(f"/run/{run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        run_response = RunResponse.from_json(res.text)
        assert run_response.run_id == run_id
        assert run_response.test_url


@pytest.mark.parametrize(
    "run_id, expected_status, expected_k8s_teardown, expected_delete",
    [
        (1, HTTPStatus.NO_CONTENT, True, True),
        (2, HTTPStatus.NO_CONTENT, False, True),
        (4, HTTPStatus.NO_CONTENT, False, True),
        (6, HTTPStatus.NOT_FOUND, False, False),  # Another user owns this run
        (99, HTTPStatus.NOT_FOUND, False, False),  # run DNE
    ],
)
@pytest.mark.asyncio
async def test_delete_individual_run(
    client,
    pg_base_config,
    valid_jwt_user1,
    k8s_mock: MockedK8s,
    run_id: int,
    expected_status: HTTPStatus,
    expected_k8s_teardown: bool,
    expected_delete: bool,
):
    """Can individual runs be deleted for a specific user"""

    # Act
    async with generate_async_session(pg_base_config) as session:
        before_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()

    response = await client.delete(f"/run/{run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert response.status_code == expected_status
    async with generate_async_session(pg_base_config) as session:
        after_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()
        db_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one_or_none()

        if expected_delete:
            assert after_run_count == before_run_count - 1
            assert db_run is None
        else:
            assert after_run_count == before_run_count

    if expected_k8s_teardown:
        k8s_mock.delete_service.assert_called_once()
        k8s_mock.delete_statefulset.assert_called_once()
        k8s_mock.remove_ingress_rule.assert_called_once()
    else:
        k8s_mock.delete_service.assert_not_called()
        k8s_mock.delete_statefulset.assert_not_called()
        k8s_mock.remove_ingress_rule.assert_not_called()


@pytest.mark.parametrize(
    "runner_status, expected",
    [
        (None, None),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(True, "", ""), CriteriaEntry(True, "", "")],
                request_history=[
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", [], 0),
                    RequestEntry("", "", HTTPMethod.POST, HTTPStatus.OK, datetime.now(), "", None, 0),
                ],
            ),
            True,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[],
                request_history=[],
            ),
            True,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=None,
                request_history=None,
            ),
            True,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(True, "", ""), CriteriaEntry(True, "", "")],
                request_history=[
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", None, 0),
                    RequestEntry("", "", HTTPMethod.POST, HTTPStatus.OK, datetime.now(), "", ["validation error"], 0),
                ],
            ),
            False,
        ),  # validation error
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(True, "", ""), CriteriaEntry(False, "", "")],
                request_history=[
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", None, 0),
                    RequestEntry("", "", HTTPMethod.POST, HTTPStatus.OK, datetime.now(), "", [], 0),
                ],
            ),
            False,
        ),  # criteria error
    ],
)
def test_is_all_criteria_met(runner_status: RunnerStatus | None, expected: bool | None):
    actual = is_all_criteria_met(runner_status)
    assert actual is expected


@pytest.mark.parametrize(
    "runner_status, all_criteria_met",
    [
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(True, "", "")],
                request_history=[RequestEntry("a", "b", "c", HTTPStatus.OK, datetime(2022, 11, 20), "", [], 0)],
            ),
            True,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={},
                criteria=[CriteriaEntry(False, "", "")],
                request_history=[],
            ),
            False,
        ),
        (
            generate_class_instance(
                RunnerStatus,
                step_status={"step1": StepStatus.RESOLVED},
                criteria=[CriteriaEntry(True, "", "")],
                request_history=[
                    RequestEntry("a", "b", "c", HTTPStatus.OK, datetime(2022, 11, 20), "", ["an error"], 0)
                ],
            ),
            False,
        ),
    ],
)
@pytest.mark.asyncio
async def test_finalise_run_creates_run_artifact_and_updates_run(
    pg_base_config, k8s_mock: MockedK8s, runner_status, all_criteria_met
):
    """Finalize correctly updates the DB with data requested from the runner"""
    # Arrange
    finalize_data = b"file_data"

    k8s_mock.status.return_value = runner_status
    k8s_mock.finalize.return_value = finalize_data
    finalise_time = datetime(2023, 4, 5, tzinfo=timezone.utc)
    timeout_seconds = 10

    # Act
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == 1))).scalar_one()
        result = await finalise_run(
            run, "http://mockurl", session, RunStatus.finalised_by_client, finalise_time, timeout_seconds
        )
        assert isinstance(result, RunArtifact)

    # Assert
    k8s_mock.status.assert_called_once()
    k8s_mock.finalize.assert_called_once()
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at == finalise_time
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is all_criteria_met
        assert run.run_artifact.file_data == finalize_data


@pytest.mark.asyncio
async def test_finalise_run_handles_runner_finalize_failure(
    pg_base_config,
    k8s_mock: MockedK8s,
):
    """Finalize still updates the record as finalised even if runner misbehaves"""
    # Arrange
    runner_status = generate_class_instance(
        RunnerStatus, step_status={"step1": StepStatus.RESOLVED}, request_history=[]
    )  # This is a success status

    k8s_mock.status.return_value = runner_status
    k8s_mock.finalize.side_effect = Exception("mock exception")
    finalise_time = datetime(2023, 4, 5, tzinfo=timezone.utc)
    timeout_seconds = 10

    # Act
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == 1))).scalar_one()
        result = await finalise_run(
            run, "http://mockurl", session, RunStatus.finalised_by_client, finalise_time, timeout_seconds
        )
        assert result is None

    # Assert
    k8s_mock.status.assert_called_once()
    k8s_mock.finalize.assert_called_once()
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at == finalise_time
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is True
        assert run.run_artifact is None


@pytest.mark.asyncio
async def test_finalise_run_handles_runner_status_failure(
    pg_base_config,
    k8s_mock: MockedK8s,
):
    """Finalize will still proceed even if the runner status cannot be determined"""
    # Arrange
    finalize_data = b"file_data"

    k8s_mock.status.side_effect = Exception("my mock exception")
    k8s_mock.finalize.return_value = finalize_data
    finalise_time = datetime(2023, 4, 5, tzinfo=timezone.utc)
    timeout_seconds = 10

    # Act
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == 1))).scalar_one()
        result = await finalise_run(
            run, "http://mockurl", session, RunStatus.finalised_by_client, finalise_time, timeout_seconds
        )
        assert isinstance(result, RunArtifact)

    # Assert
    k8s_mock.status.assert_called_once()
    k8s_mock.finalize.assert_called_once()
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at == finalise_time
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is None
        assert run.run_artifact.file_data == finalize_data


@pytest.mark.asyncio
async def test_finalise_run_and_teardown_teststack_success(client, pg_base_config, k8s_mock, valid_jwt_user1):
    # Arrange
    finalize_data = b"\x1f\x8b\x08\x00I\xe9\xe4g\x02\xff\xcb,)N\xccM\xf5M,\xca\xcc\x07\x00\xcd\xcc5\xc5\x0b\x00\x00\x00"
    k8s_mock.finalize.return_value = finalize_data
    k8s_mock.status.return_value = generate_class_instance(RunnerStatus, step_status={})

    # Act
    response = await client.post("/run/1/finalise", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert response.status_code == 200
    assert response.content == finalize_data

    k8s_mock.finalize.assert_called_once()
    k8s_mock.status.assert_called_once()

    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert_nowish(run.finalised_at)
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is True
        assert run.run_artifact.file_data == finalize_data


@pytest.mark.asyncio
async def test_finalise_run_and_teardown_teststack_idempotent(client, pg_base_config, k8s_mock, valid_jwt_user1):
    """Tests that finalising the same run multiple times will not cause any weird side effects"""

    # Arrange
    finalize_data = b"\x1f\x8b\x08\x00I\xe9\xe4g\x02\xff\xcb,)N\xccM\xf5M,\xca\xcc\x07\x00\xcd\xcc5\xc5\x0b\x00\x00\x00"
    k8s_mock.finalize.side_effect = [finalize_data, Exception("Mock exception - shouldn't be raised")]
    k8s_mock.status.side_effect = [
        generate_class_instance(RunnerStatus, step_status={}),
        Exception("Mock exception - shouldn't be raised"),
    ]

    # First request should perform normally and update the DB
    response1 = await client.post("/run/1/finalise", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response1.status_code == 200
    assert response1.content == finalize_data
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        original_finalised_at = run.finalised_at

        assert_nowish(run.finalised_at)
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is True
        assert run.run_artifact.file_data == finalize_data

    # We should've only cleaned up and finalised once (for the first request)
    k8s_mock.delete_statefulset.assert_called_once()
    k8s_mock.remove_ingress_rule.assert_called_once()
    k8s_mock.delete_service.assert_called_once()
    k8s_mock.finalize.assert_called_once()
    k8s_mock.status.assert_called_once()

    # Fire off the same request again - it should return the exact same data and the DB should still be OK
    response2 = await client.post("/run/1/finalise", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response2.status_code == 200
    assert response2.content == finalize_data
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at == original_finalised_at, "This shouldn't have changed"
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is True
        assert run.run_artifact.file_data == finalize_data

    # We should've only cleaned up and finalised once (for the first request)
    k8s_mock.delete_statefulset.assert_called_once()
    k8s_mock.remove_ingress_rule.assert_called_once()
    k8s_mock.delete_service.assert_called_once()
    k8s_mock.finalize.assert_called_once()
    k8s_mock.status.assert_called_once()


@pytest.mark.parametrize(
    "run_id, expected_status",
    [
        (1, HTTPStatus.OK),
        (5, HTTPStatus.OK),
        (8, HTTPStatus.OK),
        (2, HTTPStatus.GONE),
        (6, HTTPStatus.NOT_FOUND),
        (99, HTTPStatus.NOT_FOUND),
    ],
)
async def test_get_run_status(k8s_mock, client, pg_base_config, valid_jwt_user1, run_id, expected_status):
    """Does fetching the run status work under success conditions"""

    # Act
    status_response_data = generate_class_instance(RunnerStatus, generate_relationships=True, step_status={})
    k8s_mock.status.return_value = status_response_data

    res = await client.get(f"run/{run_id}/status", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

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
    [
        (1, HTTPStatus.OK),
        (5, HTTPStatus.OK),
        (8, HTTPStatus.OK),
        (2, HTTPStatus.GONE),
        (6, HTTPStatus.NOT_FOUND),
        (99, HTTPStatus.NOT_FOUND),
    ],
)
async def test_get_run_request_list(k8s_mock, client, pg_base_config, valid_jwt_user1, run_id, expected_status):
    """Does fetching the run request list work under common conditions"""

    # Act
    expected_request_list = generate_class_instance(RequestList)
    k8s_mock.list_requests.return_value = expected_request_list

    res = await client.get(f"run/{run_id}/requests", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        actual_list = RequestList.from_dict(res.json())
        assert actual_list == expected_request_list
        k8s_mock.list_requests.assert_called_once()
    else:
        k8s_mock.list_requests.assert_not_called()


@pytest.mark.parametrize(
    "run_id, expected_status",
    [
        (1, HTTPStatus.OK),
        (5, HTTPStatus.OK),
        (8, HTTPStatus.OK),
        (2, HTTPStatus.GONE),
        (6, HTTPStatus.NOT_FOUND),
        (99, HTTPStatus.NOT_FOUND),
    ],
)
async def test_get_run_request_data(
    k8s_mock: MockedK8s, client, pg_base_config, valid_jwt_user1, run_id, expected_status
):
    """Does fetching the run request list work under common conditions"""

    # Act
    request_id = 315163161
    expected_request_data = generate_class_instance(RequestData)
    k8s_mock.get_request.return_value = expected_request_data

    res = await client.get(
        f"run/{run_id}/requests/{request_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        actual_request = RequestData.from_dict(res.json())
        assert actual_request == expected_request_data
        k8s_mock.get_request.assert_called_once()
        assert (
            k8s_mock.get_request.call_args_list[0].args[1] == request_id
        )  # Ensuring request_id is passed to runner client
    else:
        k8s_mock.get_request.assert_not_called()


@pytest.mark.parametrize(
    "run_id,expected_status,expected_artifact_id,expected_user,expected_test_id,expected_group_name,expected_group_id",
    [
        (1, HTTPStatus.NOT_FOUND, None, None, None, None, None),
        (2, HTTPStatus.OK, 1, "user1@cactus.example.com", "ALL-01", "name-1", "1"),
        (4, HTTPStatus.OK, 2, "user1@cactus.example.com", "ALL-03", "name-1", "1"),
        (5, HTTPStatus.OK, 3, "user1@cactus.example.com", "ALL-01", "name-2", "2"),
        (6, HTTPStatus.NOT_FOUND, None, None, None, None, None),  # Other user
        (99, HTTPStatus.NOT_FOUND, None, None, None, None, None),  # DNE
    ],
)
async def test_get_run_artifact_data(
    k8s_mock: MockedK8s,
    client,
    pg_base_config,
    valid_jwt_user1,
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
    res = await client.get(f"run/{run_id}/artifact", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:

        assert expected_artifact_data == res.read()

        assert res.headers[HEADER_USER_NAME] == expected_user
        assert res.headers[HEADER_TEST_ID] == expected_test_id
        assert res.headers[HEADER_RUN_ID] == str(run_id)
        assert res.headers[HEADER_GROUP_ID] == expected_group_id
        assert res.headers[HEADER_GROUP_NAME] == expected_group_name


@pytest.mark.asyncio
async def test_spawn_teststack_with_playlist(
    client, k8s_mock: MockedK8s, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    subscription_domain = "playlist.test"
    run_group_id = 1

    k8s_mock.health.return_value = True
    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain
        user.is_static_uri = False

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = True

        await session.commit()

    # Act - Create playlist with multiple tests
    req = InitRunRequest(test_procedure_ids=[TestProcedureId.ALL_01.value, TestProcedureId.ALL_02.value])
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model = InitRunResponse.from_json(res.text)
    assert os.environ["TEST_EXECUTION_FQDN"] in response_model.test_url
    assert response_model.playlist_execution_id is not None
    assert response_model.playlist_runs is not None
    assert len(response_model.playlist_runs) == 2

    # Check playlist run details - order is implicit in array position
    assert response_model.playlist_runs[0].test_procedure_id == TestProcedureId.ALL_01.value
    assert response_model.playlist_runs[1].test_procedure_id == TestProcedureId.ALL_02.value

    # Check k8s - only ONE teststack should be created
    k8s_mock.clone_statefulset.assert_called_once()
    k8s_mock.clone_service.assert_called_once()
    k8s_mock.add_ingress_rule.assert_called_once()
    k8s_mock.wait_for_pod.assert_called_once()
    k8s_mock.init.assert_awaited_once()

    # DB - all runs created with correct statuses
    async with generate_async_session(pg_base_config) as session:
        from cactus_orchestrator.crud import select_playlist_runs

        playlist_runs = await select_playlist_runs(session, response_model.playlist_execution_id)
        assert len(playlist_runs) == 2
        assert playlist_runs[0].run_status == RunStatus.initialised  # First run
        assert playlist_runs[1].run_status == RunStatus.initialised  # Second run
        assert all(r.teststack_id == playlist_runs[0].teststack_id for r in playlist_runs)  # Same teststack


@pytest.mark.asyncio
async def test_backwards_compatibility_single_run(
    client, k8s_mock: MockedK8s, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    subscription_domain = "single.test"
    run_group_id = 1

    k8s_mock.health.return_value = True
    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain
        user.is_static_uri = False

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = True

        await session.commit()

    # Act - Use old single test_procedure_id format
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01.value)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model = InitRunResponse.from_json(res.text)
    assert response_model.playlist_execution_id is None
    assert response_model.playlist_runs is None or len(response_model.playlist_runs) == 0

    # DB - run should have NULL playlist fields
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == response_model.run_id))).scalar_one()
        assert run.playlist_execution_id is None
        assert run.playlist_order is None
        assert run.testprocedure_id == TestProcedureId.ALL_01.value


async def create_playlist_for_test(
    client,
    k8s_mock: MockedK8s,
    pg_base_config,
    client_cert_pem_bytes: bytes,
    valid_jwt: str,
    test_procedure_ids: list[str],
    run_group_id: int = 1,
) -> InitRunResponse:
    """Helper to set up k8s mocks, configure user/run_group, and create a playlist."""
    k8s_mock.health.return_value = True
    k8s_mock.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = "playlist.test"
        user.is_static_uri = False

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = True

        await session.commit()

    req = InitRunRequest(test_procedure_ids=test_procedure_ids)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt}"}
    )
    assert res.status_code == HTTPStatus.CREATED
    return InitRunResponse.from_json(res.text)


@pytest.mark.asyncio
async def test_playlist_finalize_advances_to_next_test(
    client, k8s_mock: MockedK8s, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        k8s_mock,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01.value, TestProcedureId.ALL_02.value],
    )
    first_run_id = response_model.playlist_runs[0].run_id
    second_run_id = response_model.playlist_runs[1].run_id

    # Update first run to started status
    async with generate_async_session(pg_base_config) as session:
        await session.execute(update(Run).where(Run.run_id == first_run_id).values(run_status=RunStatus.started))
        await session.commit()

    # Mock runner status to report second test is now active (simulating advancement)
    finalize_data = b"\x1f\x8b\x08\x00test_data"
    k8s_mock.finalize.return_value = finalize_data
    k8s_mock.status.return_value = generate_class_instance(
        RunnerStatus,
        test_procedure_name=TestProcedureId.ALL_02.value,  # Runner reports next test is active
        step_status={},
    )

    # Finalize first run
    response = await client.post(
        f"/run/{first_run_id}/finalise", headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )
    assert response.status_code == HTTPStatus.OK

    # Assert - teststack should NOT be torn down, second run should be started
    k8s_mock.delete_statefulset.assert_not_called()
    k8s_mock.delete_service.assert_not_called()

    async with generate_async_session(pg_base_config) as session:
        first_run = (await session.execute(select(Run).where(Run.run_id == first_run_id))).scalar_one()
        second_run = (await session.execute(select(Run).where(Run.run_id == second_run_id))).scalar_one()

        assert first_run.run_status == RunStatus.finalised_by_client
        assert second_run.run_status == RunStatus.started  # Advanced to next test


@pytest.mark.asyncio
async def test_playlist_finalize_teardown_on_last_test(
    client, k8s_mock: MockedK8s, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        k8s_mock,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01.value, TestProcedureId.ALL_02.value],
    )
    first_run_id = response_model.playlist_runs[0].run_id
    second_run_id = response_model.playlist_runs[1].run_id

    # Set up state: first run already finalized, second run is active
    async with generate_async_session(pg_base_config) as session:
        await session.execute(
            update(Run).where(Run.run_id == first_run_id).values(run_status=RunStatus.finalised_by_client)
        )
        await session.execute(update(Run).where(Run.run_id == second_run_id).values(run_status=RunStatus.started))
        await session.commit()

    # Mock runner status to report no active test (playlist complete)
    finalize_data = b"\x1f\x8b\x08\x00test_data"
    k8s_mock.finalize.return_value = finalize_data
    k8s_mock.status.return_value = generate_class_instance(
        RunnerStatus,
        test_procedure_name="-",  # No active test - playlist complete
        step_status={},
    )

    # Finalize last run
    response = await client.post(
        f"/run/{second_run_id}/finalise", headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )
    assert response.status_code == HTTPStatus.OK

    # Assert - teststack should be torn down
    k8s_mock.delete_statefulset.assert_called_once()
    k8s_mock.delete_service.assert_called_once()
    k8s_mock.remove_ingress_rule.assert_called_once()

    async with generate_async_session(pg_base_config) as session:
        second_run = (await session.execute(select(Run).where(Run.run_id == second_run_id))).scalar_one()
        assert second_run.run_status == RunStatus.finalised_by_client


@pytest.mark.asyncio
async def test_delete_playlist_run_deletes_all_siblings(
    client, k8s_mock: MockedK8s, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        k8s_mock,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01.value, TestProcedureId.ALL_02.value, TestProcedureId.ALL_03.value],
    )
    run_ids = [r.run_id for r in response_model.playlist_runs]

    # Verify runs exist
    async with generate_async_session(pg_base_config) as session:
        runs = (await session.execute(select(Run).where(Run.run_id.in_(run_ids)))).scalars().all()
        assert len(runs) == 3

    # Delete the second run (middle of playlist)
    response = await client.delete(f"/run/{run_ids[1]}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response.status_code == HTTPStatus.NO_CONTENT

    # Assert - teststack should be torn down
    k8s_mock.delete_statefulset.assert_called_once()
    k8s_mock.delete_service.assert_called_once()

    # All runs should be deleted
    async with generate_async_session(pg_base_config) as session:
        remaining_runs = (await session.execute(select(Run).where(Run.run_id.in_(run_ids)))).scalars().all()
        assert len(remaining_runs) == 0


@pytest.mark.asyncio
async def test_get_individual_run_returns_playlist_total(
    client, k8s_mock: MockedK8s, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        k8s_mock,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01.value, TestProcedureId.ALL_02.value, TestProcedureId.ALL_03.value],
    )

    # Get first run details
    first_run_id = response_model.playlist_runs[0].run_id
    response = await client.get(f"/run/{first_run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response.status_code == HTTPStatus.OK

    run_response = RunResponse.from_json(response.text)
    assert run_response.playlist_execution_id is not None
    assert run_response.playlist_order == 0
    assert run_response.playlist_total == 3


@pytest.mark.asyncio
async def test_start_run_rejects_out_of_order_playlist_run(
    client, k8s_mock: MockedK8s, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        k8s_mock,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01.value, TestProcedureId.ALL_02.value],
    )
    first_run_id = response_model.playlist_runs[0].run_id
    second_run_id = response_model.playlist_runs[1].run_id

    # Try to start the second run while first is still active
    response = await client.post(f"/run/{second_run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Should be rejected with CONFLICT
    assert response.status_code == HTTPStatus.CONFLICT
    assert str(first_run_id) in response.text
