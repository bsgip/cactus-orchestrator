import io
import os
import shutil
import tempfile
import zipfile
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPMethod, HTTPStatus
from itertools import product
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from assertical.asserts.time import assert_nowish
from assertical.fake.generator import generate_class_instance
from assertical.fixtures.postgres import generate_async_session
from cactus_runner.client import RunnerClientError
from cactus_schema.orchestrator import (
    HEADER_GROUP_ID,
    HEADER_GROUP_NAME,
    HEADER_RUN_ID,
    HEADER_TEST_ID,
    HEADER_USER_NAME,
    InitRunRequest,
    InitRunResponse,
    ProceedResponse,
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
from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User
from cactus_orchestrator.pod.models import generate_dynamic_uri_external_host, generate_static_uri_external_host


@dataclass
class MockedPod:
    # Podman lifecycle
    create_pod_run: AsyncMock
    destroy_pod_resources: AsyncMock
    ensure_images: AsyncMock

    # Runner client
    init: Mock
    start: Mock
    finalize: Mock
    status: Mock
    health: Mock
    last_interaction: Mock
    list_requests: Mock
    get_request: Mock
    proceed: Mock


@pytest.fixture
def mocked_pod() -> Generator[MockedPod, None, None]:
    with (
        patch("cactus_orchestrator.api.run.create_pod_run", new_callable=AsyncMock) as mock_create_pod_run,
        patch(
            "cactus_orchestrator.api.run.destroy_pod_resources", new_callable=AsyncMock
        ) as mock_destroy_pod_resources,
        patch("cactus_orchestrator.api.run.ensure_images", new_callable=AsyncMock) as mock_ensure_images,
        patch("cactus_orchestrator.api.run.RunnerClient.initialise") as init,
        patch("cactus_orchestrator.api.run.RunnerClient.start") as start,
        patch("cactus_orchestrator.api.run.RunnerClient.finalize") as finalize,
        patch("cactus_orchestrator.api.run.RunnerClient.status") as status,
        patch("cactus_orchestrator.api.run.RunnerClient.last_interaction") as last_interaction,
        patch("cactus_orchestrator.api.run.RunnerClient.health") as health,
        patch("cactus_orchestrator.api.run.RunnerClient.list_requests") as list_requests,
        patch("cactus_orchestrator.api.run.RunnerClient.get_request") as get_request,
        patch("cactus_orchestrator.api.run.RunnerClient.proceed") as proceed,
    ):
        # create_pod_run returns pod_name
        async def create_pod_run_side_effect(podman_socket: str, images, resources, routes):
            return resources.pod_name

        mock_create_pod_run.side_effect = create_pod_run_side_effect

        yield MockedPod(
            create_pod_run=mock_create_pod_run,
            destroy_pod_resources=mock_destroy_pod_resources,
            ensure_images=mock_ensure_images,
            init=init,
            start=start,
            finalize=finalize,
            status=status,
            last_interaction=last_interaction,
            health=health,
            list_requests=list_requests,
            get_request=get_request,
            proceed=proceed,
        )


@pytest.fixture
def zip_file_data(reporting_data_json, reporting_data_version) -> bytes:
    json_reporting_data = reporting_data_json

    # Work in a temporary directory
    with tempfile.TemporaryDirectory() as tempdirname:
        base_path = Path(tempdirname)

        # All the test procedure artifacts should be placed in `archive_dir` to be archived
        archive_dir = base_path / "archive"
        os.mkdir(archive_dir)

        # Create reporting data json file
        if json_reporting_data is not None:
            file_path = archive_dir / f"ReportingData_v{reporting_data_version}.json"
            with open(file_path, "w") as f:
                f.write(json_reporting_data)

        # Create the temporary zip file
        ARCHIVE_BASEFILENAME = "finalize"
        ARCHIVE_KIND = "zip"
        shutil.make_archive(str(base_path / ARCHIVE_BASEFILENAME), ARCHIVE_KIND, archive_dir)

        # Read the zip file contents as binary
        archive_path = base_path / f"{ARCHIVE_BASEFILENAME}.{ARCHIVE_KIND}"
        with open(archive_path, mode="rb") as f:
            zip_contents = f.read()
    return zip_contents


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
    mocked_pod: MockedPod,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
    is_device_cert: bool,
    run_group_id: int,
    expected_version: str,
):
    """Just a simple test of starting a run with all k8s functions stubbed under various circumstances"""

    subscription_domain = "abc.def"

    mocked_pod.health.return_value = True

    mocked_pod.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = is_device_cert
        run_group.is_static_uri = False

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model: InitRunResponse = InitRunResponse.from_json(res.text)
    assert os.environ["CACTUS_FQDN"] in response_model.test_url, "The returned URI should be public facing"
    assert res.headers["Location"] == f"/run/{response_model.run_id}"

    expected_static_uri_host = generate_static_uri_external_host(os.environ["CACTUS_FQDN"], run_group_id)
    expected_dynamic_uri_host = generate_dynamic_uri_external_host(
        os.environ["CACTUS_FQDN"], run_group_id, response_model.run_id
    )
    assert expected_dynamic_uri_host in response_model.test_url
    assert expected_static_uri_host not in response_model.test_url
    assert response_model.test_url.endswith("/dcap")

    # Check the teststack was spawned
    mocked_pod.create_pod_run.assert_awaited_once()

    # Check init was called with a single RunRequest (not a list) for backwards compatibility
    mocked_pod.init.assert_awaited_once()
    run_request = mocked_pod.init.call_args_list[0].kwargs["run_request"]
    assert isinstance(run_request, RunRequest)
    assert not isinstance(run_request, list)
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
        assert new_run.pod_name is not None and str(response_model.run_id) in new_run.pod_name
        assert_nowish(new_run.created_at)


@pytest.mark.parametrize("is_device_cert, is_started_response", product([True, False], [True, False]))
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_static_uri(
    client,
    mocked_pod: MockedPod,
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

    mocked_pod.health.return_value = True

    mocked_pod.init.return_value = generate_class_instance(InitResponseBody, is_started=is_started_response)

    async with generate_async_session(pg_base_config) as session:
        # Firstly ensure all user runs are expired before we start
        await session.execute(update(Run).values(run_status=RunStatus.terminated).where(Run.run_group_id.in_([1, 2])))

        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.is_static_uri = True
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = is_device_cert

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model: InitRunResponse = InitRunResponse.from_json(res.text)
    assert os.environ["CACTUS_FQDN"] in response_model.test_url, "The returned URI should be public facing"
    assert res.headers["Location"] == f"/run/{response_model.run_id}"

    expected_static_uri_host = generate_static_uri_external_host(os.environ["CACTUS_FQDN"], run_group_id)
    expected_dynamic_uri_host = generate_dynamic_uri_external_host(
        os.environ["CACTUS_FQDN"], run_group_id, response_model.run_id
    )
    assert expected_dynamic_uri_host not in response_model.test_url
    assert expected_static_uri_host in response_model.test_url
    assert response_model.test_url.endswith("/dcap")

    # Check the teststack was spawned
    mocked_pod.create_pod_run.assert_awaited_once()

    # Check init was called with a single RunRequest (not a list) for backwards compatibility
    mocked_pod.init.assert_awaited_once()
    run_request = mocked_pod.init.call_args_list[0].kwargs["run_request"]
    assert isinstance(run_request, RunRequest)
    assert not isinstance(run_request, list)
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
        assert new_run.pod_name is not None and str(response_model.run_id) in new_run.pod_name
        assert_nowish(new_run.created_at)


@pytest.mark.asyncio
async def test_spawn_teststack_and_init_failure_from_create(
    client,
    mocked_pod: MockedPod,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
):
    """If the pod creation fails - ensure that the everything is destroyed"""

    # Arrange
    subscription_domain = "abc.def"
    run_group_id = 1

    # Ensure the init call fails
    mocked_pod.create_pod_run.side_effect = Exception("mock error")

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_static_uri = False

        initial_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run",
        content=req.to_json(),
        headers={"Authorization": f"Bearer {valid_jwt_user1}"},
        timeout=timedelta(seconds=30),
    )

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

    # Check the teststack was spawned
    mocked_pod.create_pod_run.assert_awaited_once()
    mocked_pod.init.assert_not_called()

    async with generate_async_session(pg_base_config) as session:
        after_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()
        assert initial_run_count == after_run_count


@pytest.mark.asyncio
async def test_spawn_teststack_and_init_failure_from_init(
    client,
    mocked_pod: MockedPod,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
):
    """If the call to init runner is failing - ensure that the init is aborted and the test stack is torn down"""

    # Arrange
    subscription_domain = "abc.def"
    run_group_id = 1

    # Ensure the init call fails
    mocked_pod.init.side_effect = RunnerClientError("Fake error")

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_static_uri = False

        initial_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run",
        content=req.to_json(),
        headers={"Authorization": f"Bearer {valid_jwt_user1}"},
        timeout=timedelta(seconds=30),
    )

    # Assert
    assert res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR

    # Check the teststack was spawned then torn down when the runner client init called failed
    mocked_pod.create_pod_run.assert_awaited_once()
    mocked_pod.init.assert_awaited_once()
    mocked_pod.destroy_pod_resources.assert_awaited_once()

    async with generate_async_session(pg_base_config) as session:
        after_run_count = (await session.execute(select(func.count()).select_from(Run))).scalar_one()
        assert initial_run_count == after_run_count


@pytest.mark.parametrize(
    "is_device_cert",
    [True, False],
)
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_static_uri_collision(
    client,
    mocked_pod: MockedPod,
    pg_base_config,
    client_cert_pem_bytes,
    valid_jwt_user1,
    is_device_cert: bool,
):
    """Starting a static URI run should fail if there is an existing run for the run group"""

    subscription_domain = "abc.def"
    run_group_id = 1  # There are already running runs (in the db) under this run_group

    mocked_pod.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = is_device_cert
        run_group.is_static_uri = True

        await session.commit()

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CONFLICT

    # Check the teststack was NOT spawned
    mocked_pod.create_pod_run.assert_not_awaited()


@pytest.mark.parametrize("run_group_id", [3, 99])
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_bad_run_group_id(
    client,
    mocked_pod: MockedPod,
    valid_jwt_user1,
    run_group_id: int,
):
    """Can't start a run for a run group outside user's scope"""

    # Act
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.FORBIDDEN

    # Check the teststack was NOT spawned
    mocked_pod.create_pod_run.assert_not_awaited()


@pytest.mark.parametrize(
    "is_device_cert",
    [True, False],
)
@pytest.mark.asyncio
async def test_spawn_teststack_and_init_run_expired_certs(
    client,
    mocked_pod: MockedPod,
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
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.EXPECTATION_FAILED

    # Check the teststack was NOT spawned
    mocked_pod.create_pod_run.assert_not_awaited()


@pytest.mark.parametrize("run_id, expected_success", [(6, True), (1, False), (99, False)])
@pytest.mark.asyncio
async def test_start_run(
    client, mocked_pod: MockedPod, pg_base_config, valid_jwt_user2, run_id: int, expected_success: bool
):
    """Can a user start runs that are visible to them?"""

    # Act
    res = await client.post(f"/run/{run_id}", headers={"Authorization": f"Bearer {valid_jwt_user2}"})

    # Assert
    if expected_success:
        assert res.status_code == HTTPStatus.OK
        response_model: StartRunResponse = StartRunResponse.from_json(res.text)
        assert os.environ["CACTUS_FQDN"] in response_model.test_url, "The returned URI should be public facing"

        mocked_pod.start.assert_called_once()

        async with generate_async_session(pg_base_config) as session:
            new_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one()
            assert new_run.run_status == RunStatus.started
    else:
        assert res.status_code == HTTPStatus.NOT_FOUND

        mocked_pod.start.assert_not_called()

        async with generate_async_session(pg_base_config) as session:
            new_run = (await session.execute(select(Run).where(Run.run_id == run_id))).scalar_one_or_none()
            if new_run is not None:
                assert new_run.run_status == RunStatus.initialised


@pytest.mark.asyncio
async def test_start_run_precondition_failed(client, mocked_pod: MockedPod, pg_base_config, valid_jwt_user1):
    """Will a precondition failed error from the runner proxy the right info to the client"""

    # Arrange
    error_message = "my mock error message"
    mocked_pod.start.side_effect = RunnerClientError(
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
    "run_id, expected_status, expected_pod_teardown, expected_delete",
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
    mocked_pod: MockedPod,
    run_id: int,
    expected_status: HTTPStatus,
    expected_pod_teardown: bool,
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

    if expected_pod_teardown:
        mocked_pod.destroy_pod_resources.assert_awaited_once()
    else:
        mocked_pod.destroy_pod_resources.assert_not_awaited()


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
                    RequestEntry("", "", HTTPMethod.POST, HTTPStatus.OK, datetime.now(), "", [], 0),
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
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", [], 0),
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
                    RequestEntry("", "", HTTPMethod.GET, HTTPStatus.BAD_REQUEST, datetime.now(), "", [], 0),
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
                request_history=[
                    RequestEntry("a", "b", HTTPMethod.TRACE, HTTPStatus.OK, datetime(2022, 11, 20), "", [], 0)
                ],
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
                    RequestEntry("a", "b", HTTPMethod.TRACE, HTTPStatus.OK, datetime(2022, 11, 20), "", ["an error"], 0)
                ],
            ),
            False,
        ),
    ],
)
@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.regenerate_pdf_report")
async def test_finalise_run_creates_run_artifact_and_updates_run(
    regenerate_mock, pg_base_config, mocked_pod: MockedPod, zip_file_data: bytes, runner_status, all_criteria_met
):
    """Finalize correctly updates the DB with data requested from the runner"""
    # Arrange
    finalize_data = zip_file_data

    mocked_pod.status.return_value = runner_status
    mocked_pod.finalize.return_value = finalize_data
    finalise_time = datetime(2023, 4, 5, tzinfo=UTC)
    timeout_seconds = 10
    regenerate_mock.return_value = finalize_data

    # Act
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == 1))).scalar_one()
        result = await finalise_run(
            run, "http://mockurl", session, RunStatus.finalised_by_client, finalise_time, timeout_seconds
        )
        assert isinstance(result, RunArtifact)

    # Assert
    mocked_pod.status.assert_called_once()
    mocked_pod.finalize.assert_called_once()
    regenerate_mock.assert_called_once()

    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at == finalise_time
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is all_criteria_met
        assert run.run_artifact.file_data == finalize_data


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.regenerate_pdf_report")
async def test_finalise_run_handles_runner_finalize_failure(
    regenerate_mock,
    pg_base_config,
    mocked_pod: MockedPod,
):
    """Finalize still updates the record as finalised even if runner misbehaves"""
    # Arrange
    runner_status = generate_class_instance(
        RunnerStatus, step_status={"step1": StepStatus.RESOLVED}, request_history=[]
    )  # This is a success status

    mocked_pod.status.return_value = runner_status
    mocked_pod.finalize.side_effect = Exception("mock exception")
    finalise_time = datetime(2023, 4, 5, tzinfo=UTC)
    timeout_seconds = 10
    regenerate_mock.return_value = b""

    # Act
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == 1))).scalar_one()
        result = await finalise_run(
            run, "http://mockurl", session, RunStatus.finalised_by_client, finalise_time, timeout_seconds
        )
        assert result is None

    # Assert
    mocked_pod.status.assert_called_once()
    mocked_pod.finalize.assert_called_once()
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at == finalise_time
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is True
        assert run.run_artifact is None


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.regenerate_pdf_report")
async def test_finalise_run_handles_runner_status_failure(
    regenerate_mock,
    pg_base_config,
    mocked_pod: MockedPod,
    zip_file_data: bytes,
):
    """Finalize will still proceed even if the runner status cannot be determined"""
    # Arrange
    finalize_data = zip_file_data

    mocked_pod.status.side_effect = Exception("my mock exception")
    mocked_pod.finalize.return_value = finalize_data
    finalise_time = datetime(2023, 4, 5, tzinfo=UTC)
    timeout_seconds = 10
    regenerate_mock.return_value = finalize_data

    # Act
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == 1))).scalar_one()
        result = await finalise_run(
            run, "http://mockurl", session, RunStatus.finalised_by_client, finalise_time, timeout_seconds
        )
        assert isinstance(result, RunArtifact)

    # Assert
    mocked_pod.status.assert_called_once()
    mocked_pod.finalize.assert_called_once()
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at == finalise_time
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is None
        assert run.run_artifact.file_data == finalize_data


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.regenerate_pdf_report")
async def test_finalise_run_and_teardown_teststack_success(
    regenerate_mock, client, pg_base_config, mocked_pod, zip_file_data, valid_jwt_user1
):
    # Arrange
    finalize_data = zip_file_data
    mocked_pod.finalize.return_value = finalize_data
    mocked_pod.status.return_value = generate_class_instance(RunnerStatus, step_status={})
    regenerate_mock.return_value = finalize_data

    # Act
    response = await client.post("/run/1/finalise", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert response.status_code == 200
    assert response.content == finalize_data

    mocked_pod.finalize.assert_called_once()
    mocked_pod.status.assert_called_once()

    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        assert run.finalised_at is not None
        assert_nowish(run.finalised_at)
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is True
        assert run.run_artifact.file_data == finalize_data


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.regenerate_pdf_report")
async def test_finalise_run_and_teardown_teststack_idempotent(
    regenerate_mock, client, pg_base_config, mocked_pod: MockedPod, zip_file_data, valid_jwt_user1
):
    """Tests that finalising the same run multiple times will not cause any weird side effects"""

    # Arrange
    finalize_data = zip_file_data
    mocked_pod.finalize.side_effect = [finalize_data, Exception("Mock exception - shouldn't be raised")]
    mocked_pod.status.side_effect = [
        generate_class_instance(RunnerStatus, step_status={}),
        Exception("Mock exception - shouldn't be raised"),
    ]
    regenerate_mock.return_value = finalize_data

    # First request should perform normally and update the DB
    response1 = await client.post("/run/1/finalise", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response1.status_code == 200
    assert response1.content == finalize_data
    async with generate_async_session(pg_base_config) as session:
        run = (
            await session.execute(select(Run).where(Run.run_id == 1).options(selectinload(Run.run_artifact)))
        ).scalar_one()

        original_finalised_at = run.finalised_at

        assert run.finalised_at is not None
        assert_nowish(run.finalised_at)
        assert run.run_status == RunStatus.finalised_by_client
        assert run.all_criteria_met is True
        assert run.run_artifact.file_data == finalize_data

    # We should've only cleaned up and finalised once (for the first request)
    mocked_pod.destroy_pod_resources.assert_awaited_once()
    mocked_pod.finalize.assert_called_once()
    mocked_pod.status.assert_called_once()

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
    mocked_pod.destroy_pod_resources.assert_awaited_once()
    mocked_pod.finalize.assert_called_once()
    mocked_pod.status.assert_called_once()


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
async def test_get_run_status(mocked_pod, client, pg_base_config, valid_jwt_user1, run_id, expected_status):
    """Does fetching the run status work under success conditions"""

    # Act
    status_response_data = generate_class_instance(RunnerStatus, generate_relationships=True, step_status={})
    mocked_pod.status.return_value = status_response_data

    res = await client.get(f"run/{run_id}/status", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        actual_status = RunnerStatus.from_dict(res.json())
        assert actual_status == status_response_data
        mocked_pod.status.assert_called_once()
    else:
        mocked_pod.status.assert_not_called()


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
async def test_get_run_request_list(mocked_pod, client, pg_base_config, valid_jwt_user1, run_id, expected_status):
    """Does fetching the run request list work under common conditions"""

    # Act
    expected_request_list = generate_class_instance(RequestList)
    mocked_pod.list_requests.return_value = expected_request_list

    res = await client.get(f"run/{run_id}/requests", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        actual_list = RequestList.from_dict(res.json())
        assert actual_list == expected_request_list
        mocked_pod.list_requests.assert_called_once()
    else:
        mocked_pod.list_requests.assert_not_called()


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
    mocked_pod: MockedPod, client, pg_base_config, valid_jwt_user1, run_id, expected_status
):
    """Does fetching the run request list work under common conditions"""

    # Act
    request_id = 315163161
    expected_request_data = generate_class_instance(RequestData)
    mocked_pod.get_request.return_value = expected_request_data

    res = await client.get(
        f"run/{run_id}/requests/{request_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        actual_request = RequestData.from_dict(res.json())
        assert actual_request == expected_request_data
        mocked_pod.get_request.assert_called_once()
        assert (
            mocked_pod.get_request.call_args_list[0].args[1] == request_id
        )  # Ensuring request_id is passed to runner client
    else:
        mocked_pod.get_request.assert_not_called()


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
async def test_get_run_artifact_access_control(
    mocked_pod: MockedPod,
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
    """Access control and response headers for artifact download.

    Fixture file_data is not a valid zip, so BadZipFile is caught and the original bytes are served as-is.
    PDF regeneration is not triggered because reporting_data is absent on all fixture artifacts.
    """

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


def _make_zip(include_pdf: bool = False, include_error_file: bool = False) -> bytes:
    """Helper to build a minimal valid zip for artifact tests."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("CactusTestProcedureSummary.json", '{"result": "pass"}')
        if include_pdf:
            zf.writestr("CactusTestProcedureReport.pdf", b"%PDF-1.4 placeholder")
        if include_error_file:
            zf.writestr("pdf-generation-errors.txt", "Previous generation failed")
    return buf.getvalue()


@pytest.mark.asyncio
async def test_get_run_artifact_pdf_already_present__no_regeneration(
    mocked_pod: MockedPod, client, pg_base_config, valid_jwt_user1
):
    """When the artifact zip already contains a PDF, no regeneration is attempted."""
    run_id = 2  # artifact_id=1, fixture already has a PDF
    async with generate_async_session(pg_base_config) as session:
        artifact = (await session.execute(select(RunArtifact).where(RunArtifact.run_artifact_id == 1))).scalar_one()
        artifact.file_data = _make_zip(include_pdf=True)
        artifact.reporting_data = '{"version": 1}'
        artifact.version = 1
        await session.commit()

    with patch("cactus_orchestrator.api.run.regenerate_pdf_report") as mock_regen:
        res = await client.get(f"run/{run_id}/artifact", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    assert res.status_code == HTTPStatus.OK
    mock_regen.assert_not_called()


@pytest.mark.asyncio
async def test_get_run_artifact_pdf_missing_with_reporting_data__regenerates(
    mocked_pod: MockedPod, client, pg_base_config, valid_jwt_user1
):
    """When the PDF is absent and reporting data is present, the PDF is generated and saved."""
    run_id = 2  # artifact_id=1
    zip_without_pdf = _make_zip(include_pdf=False)
    zip_with_pdf = _make_zip(include_pdf=True)

    async with generate_async_session(pg_base_config) as session:
        artifact = (await session.execute(select(RunArtifact).where(RunArtifact.run_artifact_id == 1))).scalar_one()
        artifact.file_data = zip_without_pdf
        artifact.reporting_data = '{"version": 1}'
        artifact.version = 1
        await session.commit()

    with patch("cactus_orchestrator.api.run.regenerate_pdf_report", return_value=zip_with_pdf) as mock_regen:
        res = await client.get(f"run/{run_id}/artifact", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    assert res.status_code == HTTPStatus.OK
    mock_regen.assert_called_once()
    # Verify the regenerated zip (with PDF) was saved back and served
    assert res.read() == zip_with_pdf
    async with generate_async_session(pg_base_config) as session:
        artifact = (await session.execute(select(RunArtifact).where(RunArtifact.run_artifact_id == 1))).scalar_one()
        assert artifact.file_data == zip_with_pdf


@pytest.mark.asyncio
async def test_get_run_artifact_pdf_missing_no_reporting_data__warns_and_serves_original(
    mocked_pod: MockedPod, client, pg_base_config, valid_jwt_user1
):
    """When the PDF is absent and there is no reporting data, a warning is logged and the original artifact provided."""
    run_id = 2  # artifact_id=1
    zip_without_pdf = _make_zip(include_pdf=False)

    async with generate_async_session(pg_base_config) as session:
        artifact = (await session.execute(select(RunArtifact).where(RunArtifact.run_artifact_id == 1))).scalar_one()
        artifact.file_data = zip_without_pdf
        artifact.reporting_data = None
        artifact.version = None
        await session.commit()

    with patch("cactus_orchestrator.api.run.regenerate_pdf_report") as mock_regen:
        res = await client.get(f"run/{run_id}/artifact", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    assert res.status_code == HTTPStatus.OK
    mock_regen.assert_not_called()
    assert res.read() == zip_without_pdf


@pytest.mark.asyncio
async def test_get_run_artifact_pdf_missing_regeneration_fails__serves_original(
    mocked_pod: MockedPod, client, pg_base_config, valid_jwt_user1
):
    """When PDF regeneration raises, the original artifact is still served."""
    run_id = 2  # artifact_id=1
    zip_without_pdf = _make_zip(include_pdf=False)

    async with generate_async_session(pg_base_config) as session:
        artifact = (await session.execute(select(RunArtifact).where(RunArtifact.run_artifact_id == 1))).scalar_one()
        artifact.file_data = zip_without_pdf
        artifact.reporting_data = '{"version": 1}'
        artifact.version = 1
        await session.commit()

    with patch("cactus_orchestrator.api.run.regenerate_pdf_report", side_effect=ValueError("generation failed")):
        res = await client.get(f"run/{run_id}/artifact", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    assert res.status_code == HTTPStatus.OK
    assert res.read() == zip_without_pdf


@pytest.mark.asyncio
async def test_get_run_artifact_error_file_present__regenerates(
    mocked_pod: MockedPod, client, pg_base_config, valid_jwt_user1
):
    """When the artifact has a pdf-generation-errors.txt, regeneration is attempted even if no PDF is missing."""
    run_id = 2  # artifact_id=1
    zip_with_error = _make_zip(include_pdf=False, include_error_file=True)
    zip_with_pdf = _make_zip(include_pdf=True)

    async with generate_async_session(pg_base_config) as session:
        artifact = (await session.execute(select(RunArtifact).where(RunArtifact.run_artifact_id == 1))).scalar_one()
        artifact.file_data = zip_with_error
        artifact.reporting_data = '{"version": 1}'
        artifact.version = 1
        await session.commit()

    with patch("cactus_orchestrator.api.run.regenerate_pdf_report", return_value=zip_with_pdf) as mock_regen:
        res = await client.get(f"run/{run_id}/artifact", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    assert res.status_code == HTTPStatus.OK
    mock_regen.assert_called_once()
    assert res.read() == zip_with_pdf


@pytest.mark.asyncio
async def test_spawn_teststack_with_playlist(
    client, mocked_pod: MockedPod, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    subscription_domain = "playlist.test"
    run_group_id = 1

    mocked_pod.health.return_value = True
    mocked_pod.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = True
        run_group.is_static_uri = False

        await session.commit()

    # Act - Create playlist with multiple tests
    req = InitRunRequest(test_procedure_ids=[TestProcedureId.ALL_01, TestProcedureId.ALL_02])
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model: InitRunResponse = InitRunResponse.from_json(res.text)
    assert os.environ["CACTUS_FQDN"] in response_model.test_url
    assert response_model.playlist_execution_id is not None
    assert response_model.playlist_runs is not None
    assert len(response_model.playlist_runs) == 2

    # Check playlist run details - order is implicit in array position
    assert response_model.playlist_runs[0].test_procedure_id == TestProcedureId.ALL_01.value
    assert response_model.playlist_runs[1].test_procedure_id == TestProcedureId.ALL_02.value

    # Check teststack - only ONE teststack should be created
    mocked_pod.create_pod_run.assert_awaited_once()
    mocked_pod.init.assert_awaited_once()

    # Verify RunnerClient.initialise received a list of RunRequests for playlists
    run_requests = mocked_pod.init.call_args_list[0].kwargs["run_request"]
    assert isinstance(run_requests, list)
    assert len(run_requests) == 2
    assert all(isinstance(r, RunRequest) for r in run_requests)
    assert run_requests[0].test_definition.test_procedure_id == TestProcedureId.ALL_01
    assert run_requests[1].test_definition.test_procedure_id == TestProcedureId.ALL_02

    # DB - all runs created with correct statuses
    async with generate_async_session(pg_base_config) as session:
        from cactus_orchestrator.crud import select_playlist_runs

        playlist_runs = await select_playlist_runs(session, response_model.playlist_execution_id)
        assert len(playlist_runs) == 2
        assert playlist_runs[0].run_status == RunStatus.initialised  # First run
        assert playlist_runs[1].run_status == RunStatus.initialised  # Second run
        assert playlist_runs[0].pod_name
        assert all(r.pod_name == playlist_runs[0].pod_name for r in playlist_runs)  # Same pod


@pytest.mark.asyncio
async def test_backwards_compatibility_single_run(
    client, mocked_pod: MockedPod, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    subscription_domain = "single.test"
    run_group_id = 1

    mocked_pod.health.return_value = True
    mocked_pod.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = subscription_domain

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = True
        run_group.is_static_uri = False

        await session.commit()

    # Act - Use old single test_procedure_id format
    req = InitRunRequest(test_procedure_id=TestProcedureId.ALL_01)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt_user1}"}
    )

    # Assert
    assert res.status_code == HTTPStatus.CREATED
    response_model = InitRunResponse.from_json(res.text)
    assert response_model.playlist_execution_id is None
    assert response_model.playlist_runs is None or len(response_model.playlist_runs) == 0

    # Verify RunnerClient.initialise received a single RunRequest (not a list) for backwards compatibility
    mocked_pod.init.assert_awaited_once()
    run_request = mocked_pod.init.call_args_list[0].kwargs["run_request"]
    assert isinstance(run_request, RunRequest)
    assert not isinstance(run_request, list)

    # DB - run should have NULL playlist fields
    async with generate_async_session(pg_base_config) as session:
        run = (await session.execute(select(Run).where(Run.run_id == response_model.run_id))).scalar_one()
        assert run.playlist_execution_id is None
        assert run.playlist_order is None
        assert run.testprocedure_id == TestProcedureId.ALL_01.value


async def create_playlist_for_test(
    client,
    mocked_pod: MockedPod,
    pg_base_config,
    client_cert_pem_bytes: bytes,
    valid_jwt: str,
    test_procedure_ids: list[TestProcedureId],
    run_group_id: int = 1,
) -> InitRunResponse:
    """Helper to set up podman mocks, configure user/run_group, and create a playlist."""
    mocked_pod.health.return_value = True
    mocked_pod.init.return_value = generate_class_instance(InitResponseBody, is_started=False)

    async with generate_async_session(pg_base_config) as session:
        user = (await session.execute(select(User).where(User.user_id == 1))).scalar_one()
        user.subscription_domain = "playlist.test"

        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        run_group.certificate_pem = client_cert_pem_bytes
        run_group.is_device_cert = True
        run_group.is_static_uri = False

        await session.commit()

    req = InitRunRequest(test_procedure_ids=test_procedure_ids)
    res = await client.post(
        f"/run_group/{run_group_id}/run", content=req.to_json(), headers={"Authorization": f"Bearer {valid_jwt}"}
    )
    assert res.status_code == HTTPStatus.CREATED
    return InitRunResponse.from_json(res.text)


@pytest.mark.asyncio
async def test_playlist_finalize_advances_to_next_test(
    client, mocked_pod: MockedPod, zip_file_data, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        mocked_pod,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01, TestProcedureId.ALL_02],
    )
    assert response_model.playlist_runs is not None
    first_run_id = response_model.playlist_runs[0].run_id
    second_run_id = response_model.playlist_runs[1].run_id

    # Update first run to started status
    async with generate_async_session(pg_base_config) as session:
        await session.execute(update(Run).where(Run.run_id == first_run_id).values(run_status=RunStatus.started))
        await session.commit()

    # Mock runner status to report second test is now active (simulating advancement)
    finalize_data = zip_file_data
    mocked_pod.finalize.return_value = finalize_data
    mocked_pod.status.return_value = generate_class_instance(
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
    mocked_pod.destroy_pod_resources.assert_not_awaited()

    async with generate_async_session(pg_base_config) as session:
        first_run = (await session.execute(select(Run).where(Run.run_id == first_run_id))).scalar_one()
        second_run = (await session.execute(select(Run).where(Run.run_id == second_run_id))).scalar_one()

        assert first_run.run_status == RunStatus.finalised_by_client
        assert second_run.run_status == RunStatus.started  # Advanced to next test


@pytest.mark.asyncio
async def test_playlist_finalize_teardown_on_last_test(
    client, mocked_pod: MockedPod, zip_file_data, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        mocked_pod,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01, TestProcedureId.ALL_02],
    )
    assert response_model.playlist_runs is not None
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
    finalize_data = zip_file_data
    mocked_pod.finalize.return_value = finalize_data
    mocked_pod.status.return_value = generate_class_instance(
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
    mocked_pod.create_pod_run.assert_awaited_once()

    async with generate_async_session(pg_base_config) as session:
        second_run = (await session.execute(select(Run).where(Run.run_id == second_run_id))).scalar_one()
        assert second_run.run_status == RunStatus.finalised_by_client


@pytest.mark.asyncio
async def test_delete_playlist_run_deletes_all_siblings(
    client, mocked_pod: MockedPod, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        mocked_pod,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01, TestProcedureId.ALL_02, TestProcedureId.ALL_03],
    )
    assert response_model.playlist_runs is not None
    run_ids = [r.run_id for r in response_model.playlist_runs]

    # Verify runs exist
    async with generate_async_session(pg_base_config) as session:
        runs = (await session.execute(select(Run).where(Run.run_id.in_(run_ids)))).scalars().all()
        assert len(runs) == 3

    # Delete the second run (middle of playlist)
    response = await client.delete(f"/run/{run_ids[1]}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response.status_code == HTTPStatus.NO_CONTENT

    # Assert - teststack should be torn down
    mocked_pod.create_pod_run.assert_awaited_once()

    # All runs should be deleted
    async with generate_async_session(pg_base_config) as session:
        remaining_runs = (await session.execute(select(Run).where(Run.run_id.in_(run_ids)))).scalars().all()
        assert len(remaining_runs) == 0


@pytest.mark.asyncio
async def test_get_individual_run_returns_playlist_runs(
    client, mocked_pod: MockedPod, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        mocked_pod,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01, TestProcedureId.ALL_02, TestProcedureId.ALL_03],
    )

    # Get first run details
    assert response_model.playlist_runs is not None
    first_run_id = response_model.playlist_runs[0].run_id
    response = await client.get(f"/run/{first_run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert response.status_code == HTTPStatus.OK

    run_response = RunResponse.from_json(response.text)
    assert run_response.playlist_execution_id is not None
    assert run_response.playlist_order == 0
    assert run_response.playlist_runs is not None
    assert len(run_response.playlist_runs) == 3


@pytest.mark.asyncio
async def test_start_run_rejects_out_of_order_playlist_run(
    client, mocked_pod: MockedPod, pg_base_config, client_cert_pem_bytes, valid_jwt_user1
):
    response_model = await create_playlist_for_test(
        client,
        mocked_pod,
        pg_base_config,
        client_cert_pem_bytes,
        valid_jwt_user1,
        [TestProcedureId.ALL_01, TestProcedureId.ALL_02],
    )
    assert response_model.playlist_runs is not None
    first_run_id = response_model.playlist_runs[0].run_id
    second_run_id = response_model.playlist_runs[1].run_id

    # Try to start the second run while first is still active
    response = await client.post(f"/run/{second_run_id}", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Should be rejected with CONFLICT
    assert response.status_code == HTTPStatus.CONFLICT
    assert str(first_run_id) in response.text


@pytest.mark.parametrize(
    "run_id, handled, expected_status",
    [
        (1, True, HTTPStatus.OK),
        (1, False, HTTPStatus.OK),
        (5, True, HTTPStatus.OK),
        (5, False, HTTPStatus.OK),
        (2, None, HTTPStatus.GONE),
        (6, None, HTTPStatus.NOT_FOUND),
        (99, None, HTTPStatus.NOT_FOUND),
    ],
)
@pytest.mark.asyncio
async def test_proceed_proxy(
    client, mocked_pod: MockedPod, pg_base_config, valid_jwt_user1, run_id, handled, expected_status
):
    """Does fetching the run request list work under common conditions"""

    # Act
    expected_proceed_data = ProceedResponse(handled=handled)
    mocked_pod.proceed.return_value = expected_proceed_data

    res = await client.get(f"/run/{run_id}/proceed", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == expected_status
    if expected_status == HTTPStatus.OK:
        actual_proceed_data = ProceedResponse.from_json(res.text)
        assert actual_proceed_data == expected_proceed_data
        mocked_pod.proceed.assert_called_once()
    else:
        mocked_pod.proceed.assert_not_called()


@pytest.mark.asyncio
async def test_get_run_power_limit_chart_run_not_found(client, pg_base_config, valid_jwt_user1):
    res = await client.get("/run/99/power_limit_chart", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert res.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_get_run_power_limit_chart_no_artifact(client, pg_base_config, valid_jwt_user1):
    """Run 1 exists and belongs to user1 but has no artifact."""
    res = await client.get("/run/1/power_limit_chart", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert res.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.generate_power_limit_chart", return_value=None)
async def test_get_run_power_limit_chart_insufficient_data(mock_chart, client, pg_base_config, valid_jwt_user1):
    """Returns 404 when chart generation returns None (no DER data in artifact)."""
    res = await client.get("/run/5/power_limit_chart", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert res.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.asyncio
@patch("cactus_orchestrator.api.run.generate_power_limit_chart", return_value="<html>chart</html>")
async def test_get_run_power_limit_chart_ok(mock_chart, client, pg_base_config, valid_jwt_user1):
    """Returns 200 text/html when chart generation succeeds."""
    res = await client.get("/run/5/power_limit_chart", headers={"Authorization": f"Bearer {valid_jwt_user1}"})
    assert res.status_code == HTTPStatus.OK
    assert res.headers["content-type"].startswith("text/html")
    assert "<html>chart</html>" in res.text


@pytest.mark.parametrize(
    "query_params, expected_status_code, expected_run_count, jwt",
    [
        ("?passed=true", HTTPStatus.OK, 2, "valid_jwt_user1"),
        ("?passed=false", HTTPStatus.BAD_REQUEST, None, "valid_jwt_user1"),
        ("", HTTPStatus.BAD_REQUEST, None, "valid_jwt_user1"),
        ("?passed=true", HTTPStatus.OK, 0, "valid_jwt_user2"),
    ],
)
@pytest.mark.asyncio
async def test_get_run_list(
    query_params: str,
    expected_status_code: HTTPStatus,
    expected_run_count: int | None,
    jwt: str,
    client,
    pg_base_config,
    valid_jwt_user1,
    valid_jwt_user2,
):

    res = await client.get(f"/run{query_params}", headers={"Authorization": f"Bearer {eval(jwt)}"})
    assert res.status_code == expected_status_code
    if expected_status_code == HTTPStatus.OK:
        runs = RunResponse.from_json(res.text)
        assert isinstance(runs, list)
        assert len(runs) == expected_run_count
