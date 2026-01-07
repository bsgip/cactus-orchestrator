import asyncio
import logging
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Annotated

from cactus_runner.client import ClientSession, ClientTimeout, RunnerClient, RunnerClientException
from cactus_schema.orchestrator import (
    HEADER_GROUP_ID,
    HEADER_GROUP_NAME,
    HEADER_RUN_ID,
    HEADER_TEST_ID,
    HEADER_USER_NAME,
    InitRunRequest,
    InitRunResponse,
    RunResponse,
    RunStatusResponse,
    StartRunResponse,
    uri,
)
from cactus_schema.runner import RequestData, RequestList
from cactus_schema.runner import RunGroup as RunRequestRunGroup
from cactus_schema.runner import RunnerStatus, RunRequest, TestCertificates, TestConfig, TestDefinition, TestUser
from cactus_test_definitions import CSIPAusVersion
from cactus_test_definitions.client.test_procedures import get_yaml_contents
from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.api.common import select_user_or_raise, select_user_run_group_or_raise
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.crud import (
    ACTIVE_RUN_STATUSES,
    create_runartifact,
    delete_runs,
    insert_run_for_run_group,
    select_active_runs_for_user,
    select_run_group_for_user,
    select_runs_for_group,
    select_user_run,
    select_user_run_with_artifact,
    update_run_run_status,
    update_run_with_runartifact_and_finalise,
)
from cactus_orchestrator.k8s.resource import (
    RunResourceNames,
    generate_dynamic_test_stack_id,
    generate_envoy_dcap_uri,
    generate_static_test_stack_id,
    get_resource_names,
    get_template_names,
)
from cactus_orchestrator.k8s.resource.create import add_ingress_rule, clone_service, clone_statefulset, wait_for_pod
from cactus_orchestrator.k8s.resource.delete import delete_service, delete_statefulset, remove_ingress_rule
from cactus_orchestrator.model import Run, RunArtifact, RunStatus, User
from cactus_orchestrator.settings import CactusOrchestratorException, get_current_settings

logger = logging.getLogger(__name__)


router = APIRouter()


def map_run_to_run_response(run: Run) -> RunResponse:
    status = RunStatusResponse.finalised
    if run.run_status == RunStatus.initialised:
        status = RunStatusResponse.initialised
    elif run.run_status == RunStatus.started:
        status = RunStatusResponse.started
    elif run.run_status == RunStatus.provisioning:
        status = RunStatusResponse.provisioning

    return RunResponse(
        run_id=run.run_id,
        test_procedure_id=run.testprocedure_id,
        test_url=generate_envoy_dcap_uri(get_resource_names(run.teststack_id)),
        status=status,
        all_criteria_met=run.all_criteria_met,
        created_at=run.created_at,
        finalised_at=run.finalised_at,
        is_device_cert=run.is_device_cert,
        has_artifacts=run.run_artifact_id is not None,
    )


async def prepare_run_for_delete(run: Run) -> None:
    if run.run_status in ACTIVE_RUN_STATUSES:
        try:
            resource_names = get_resource_names(run.teststack_id)
            await teardown_teststack(resource_names)
        except Exception as exc:
            logger.error(f"Error tearing down test stack for run {run.run_id}", exc_info=exc)


async def wait_for_runner_health(s: ClientSession) -> None:
    """Executes the RunnerClient.health function (which works pre-init) until it successfully connects (or enough
    attempts have passed). This is primarily to avoid situations where k8's says a pod is ready to go but the runner
    is either not fully up or networking isn't routing"""

    MAX_ATTEMPTS = 5

    for attempt in range(MAX_ATTEMPTS):
        try:
            if await RunnerClient.health(s):
                logger.debug(f"Runner is healthy after attempt {attempt}")
                return
        except Exception as exc:
            logger.error(f"Failure accessing RunnerClient.health attempt {attempt}", exc_info=exc)

        # Add a slight delay to give the pod a chance to standup
        await asyncio.sleep(2)

    raise CactusOrchestratorException(
        f"Unable to fetch health from RunnerClient after {attempt+1} attempts. Will be treated as a failed start."
    )


async def get_run_artifact_response_for_user(user: User, run_id: int) -> Response:
    # get run
    try:
        run = await select_user_run_with_artifact(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Run does not exist.")

    if run.run_artifact is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="RunArtifact does not exist.")

    run_group_name = ""
    run_group = await select_run_group_for_user(db.session, user.user_id, run.run_group_id)
    if run_group is not None:
        run_group_name = run_group.name

    return Response(
        content=run.run_artifact.file_data,
        headers={
            HEADER_USER_NAME: user.user_name or user.subject_id,
            HEADER_TEST_ID: str(run.testprocedure_id),
            HEADER_RUN_ID: str(run.run_id),
            HEADER_GROUP_ID: str(run.run_group_id),
            HEADER_GROUP_NAME: run_group_name,
        },
        media_type=f"application/{run.run_artifact.compression}",
    )


@router.get(uri.RunGroupRunList, status_code=HTTPStatus.OK)
async def get_group_runs_paginated(
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    finalised: bool | None = Query(default=None),
    created_after: datetime = Query(default=None),
) -> Page[RunResponse]:
    # check permissions
    await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    # get runs
    runs = await select_runs_for_group(db.session, run_group_id, finalised=finalised, created_at_gte=created_after)

    if runs:
        resp = [map_run_to_run_response(run) for run in runs if run]
    else:
        resp = []
    return paginate(resp)


@router.post(
    uri.RunGroupRunList,
    status_code=HTTPStatus.CREATED,
)
async def spawn_teststack_and_init_run(
    test: InitRunRequest,
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    response: Response,
) -> InitRunResponse:
    """This endpoint sets up a test procedure as requested by client.
    Steps are:
        (1) Create a service/statefulset representing the isolated envoy test environment.
        (2) Init any state in the envoy environment.
        (3) Update the ingress with a path to the envoy environment.
    """
    # get user and the preferred certificate
    user, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id, with_cert=True)
    if run_group.certificate_pem is None or run_group.is_device_cert is None:
        raise HTTPException(
            HTTPStatus.EXPECTATION_FAILED,
            detail=f"Your certificate for {run_group_id} {run_group.name} must be generated before making a test run.",
        )
    client_cert = x509.load_pem_x509_certificate(run_group.certificate_pem)
    if client_cert.not_valid_after_utc < datetime.now(timezone.utc):
        raise HTTPException(
            HTTPStatus.EXPECTATION_FAILED,
            detail="Your certificate has expired. Please regenerate your certificate and try again.",
        )

    # Discover the test stack ID - check for potential conflicts
    teststack_id: str | None = None
    if user.is_static_uri:
        teststack_id = generate_static_test_stack_id(user)

        # Because this is a static URI - we need to make sure there are no running test instances with this value set
        # (otherwise we are going to cause a collision and problems)
        # This is a limitation of enabling static URIs and the user will be warned about it when enabling things
        runs = await select_active_runs_for_user(db.session, user.user_id)
        if len(runs) > 0:
            run_ids_str = ",".join((str(r.run_id) for r in runs))
            raise HTTPException(
                HTTPStatus.CONFLICT,
                detail=f"Static URIs are enabled therefore only a single run can be active. The following run IDs are still active and will need to be finalised first: {run_ids_str}.",  # noqa: E501
            )

    else:
        teststack_id = generate_dynamic_test_stack_id()

    run_resource_names = get_resource_names(teststack_id)
    template_resource_names = get_template_names(run_group.csip_aus_version)

    # Create the run in a "provisioning" state so we can access the run_id
    run_id = await insert_run_for_run_group(
        db.session, run_group_id, teststack_id, test.test_procedure_id, RunStatus.provisioning, run_group.is_device_cert
    )

    settings = get_current_settings()

    try:
        # duplicate resources
        await clone_statefulset(template_resource_names, run_resource_names)
        await clone_service(template_resource_names, run_resource_names)

        # wait for statefulset's pod
        await wait_for_pod(run_resource_names)

        # inject initial state with either the device or aggregator cert data
        async with ClientSession(
            base_url=run_resource_names.runner_base_url,
            timeout=ClientTimeout(settings.test_execution_comms_timeout_seconds),
        ) as session:

            await wait_for_runner_health(session)

            yaml_definition = get_yaml_contents(test.test_procedure_id)
            run_request = RunRequest(
                run_id=str(run_id),
                test_definition=TestDefinition(
                    test_procedure_id=test.test_procedure_id, yaml_definition=yaml_definition
                ),
                run_group=RunRequestRunGroup(
                    run_group_id="1",
                    name="group 1",
                    csip_aus_version=CSIPAusVersion(run_group.csip_aus_version),
                    test_certificates=TestCertificates(
                        aggregator=None if run_group.is_device_cert else run_group.certificate_pem.decode(),
                        device=run_group.certificate_pem.decode() if run_group.is_device_cert else None,
                    ),
                ),
                test_config=TestConfig(
                    pen=user.pen, subscription_domain=user.subscription_domain, is_static_url=user.is_static_uri
                ),
                test_user=TestUser(user_id=str(user.user_id), name="user1"),
            )
            init_result = await RunnerClient.initialise(session=session, run_request=run_request)

        # finally, include new service in ingress rule
        await add_ingress_rule(run_resource_names)

    except (CactusOrchestratorException, RunnerClientException) as exc:
        logger.info("Failure to initialise runner. Will teardown any resources.", exc_info=exc)
        await teardown_teststack(run_resource_names)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, detail="Internal Server Error")

    # commit DB changes
    new_run_status = RunStatus.started if init_result.is_started else RunStatus.initialised
    await update_run_run_status(db.session, run_id, new_run_status)
    await db.session.commit()

    # set location header
    response.headers["Location"] = f"/run/{run_id}"

    return InitRunResponse(run_id=run_id, test_url=generate_envoy_dcap_uri(run_resource_names))


@router.post(
    uri.Run,
    status_code=HTTPStatus.OK,
)
async def start_run(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> StartRunResponse:
    """Request a test run to progress to the execution phase."""
    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    # resource ids
    run_resource_names = get_resource_names(run.teststack_id)

    # request runner starts run
    settings = get_current_settings()
    async with ClientSession(
        base_url=run_resource_names.runner_base_url,
        timeout=ClientTimeout(settings.test_execution_comms_timeout_seconds),
    ) as s:
        try:
            await RunnerClient.start(s)
        except RunnerClientException as exc:
            # Runner uses 412 to indicate unmet app-level preconditions (i.e. init phase steps not completed),
            # we 'proxy' this through.
            if exc.http_status_code == HTTPStatus.PRECONDITION_FAILED:
                logger.info(
                    f"Received a precondition failure on start for user {user.user_id} run {run_id}", exc_info=exc
                )
                error_message = (
                    "One or more preconditions are incomplete or invalid"
                    if exc.error_message is None
                    else exc.error_message
                )
                raise HTTPException(HTTPStatus.PRECONDITION_FAILED, error_message)

            # raising server error as default
            logger.error(f"Received an unexpected failure on start for user {user.user_id} run {run_id}", exc_info=exc)
            raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR)

    # update status
    await update_run_run_status(session=db.session, run_id=run.run_id, run_status=RunStatus.started)
    await db.session.commit()

    return StartRunResponse(test_url=generate_envoy_dcap_uri(run_resource_names))


async def teardown_teststack(run_resource_names: RunResourceNames) -> None:
    """Tears down the envoy teststack (ingress rule + service + statefulset)"""
    # Remove ingress rule
    await remove_ingress_rule(run_resource_names)

    # Remove resources
    await delete_service(run_resource_names)
    await delete_statefulset(run_resource_names)


def is_all_criteria_met(runner_status: RunnerStatus | None) -> bool | None:

    if runner_status is None:
        return None

    criteria = runner_status.criteria if runner_status.criteria is not None else []
    request_history = runner_status.request_history if runner_status.request_history is not None else []

    return all((c.success for c in criteria)) and all((not bool(r.body_xml_errors) for r in request_history))


async def finalise_run(
    run: Run, url: str, session: AsyncSession, run_status: RunStatus, finalised_at: datetime, comms_timeout_seconds: int
) -> RunArtifact | None:

    async with ClientSession(base_url=url, timeout=ClientTimeout(comms_timeout_seconds)) as s:

        # We need our final status to evaluate whether all criteria are passing
        # But we don't want to block the finalisation if there's an issue fetching it
        try:
            final_status = await RunnerClient.status(s)
        except Exception as exc:
            logger.error("Error fetching final runner status.", exc_info=exc)
            final_status = None

        # NOTE: we are assuming that files are small, consider streaming to file store
        # if sizes increase.
        try:
            file_data = await RunnerClient.finalize(s)
        except Exception as exc:
            logger.error(f"Error finalizing run {run.run_id}", exc_info=exc)
            file_data = None
        compression = "zip"  # TODO: should also return compression or allow access to response header

    all_criteria_met = is_all_criteria_met(final_status)

    # If we were able to finalize - save the data. If not, we will still shut it down - people will be forced to redo
    if file_data:
        artifact = await create_runartifact(session, compression, file_data)
    else:
        artifact = None

    await update_run_with_runartifact_and_finalise(
        session, run, None if artifact is None else artifact.run_artifact_id, run_status, finalised_at, all_criteria_met
    )
    await session.commit()

    return artifact


@router.get(uri.Run, status_code=HTTPStatus.OK)
async def get_individual_run(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> RunResponse:

    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    return map_run_to_run_response(run)


@router.delete(uri.Run, status_code=HTTPStatus.NO_CONTENT)
async def delete_individual_run(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> None:

    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    await prepare_run_for_delete(run)
    await delete_runs(db.session, [run])
    await db.session.commit()


@router.post(uri.RunFinalise, status_code=HTTPStatus.OK)
async def finalise_run_and_teardown_teststack(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:
    """Returns 200 and a binary zip stream on success. Returns 201 if the finalize succeeded but there was an error
    fetching the finalized data. This call is idempotent - multiple calls will return the original values without
    updating the database."""
    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run_with_artifact(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    # Don't attempt to cleanup / teardown if this has already been finalised
    if run.run_status in ACTIVE_RUN_STATUSES:
        settings = get_current_settings()

        # get resource names
        run_resource_names = get_resource_names(run.teststack_id)

        # finalise
        artifact = await finalise_run(
            run,
            run_resource_names.runner_base_url,
            db.session,
            RunStatus.finalised_by_client,
            datetime.now(timezone.utc),
            settings.test_execution_comms_timeout_seconds,
        )
        await db.session.commit()

        # teardown
        await teardown_teststack(run_resource_names)
    else:
        artifact = run.run_artifact

    if artifact is None:
        return Response(status_code=HTTPStatus.NO_CONTENT)
    else:
        return Response(
            status_code=HTTPStatus.OK,
            content=artifact.file_data,
            media_type=f"application/{artifact.compression}",
        )


@router.get(uri.RunArtifact, status_code=HTTPStatus.OK)
async def get_run_artifact(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:
    """Downloads a raw binary stream of the run artifacts"""

    user = await select_user_or_raise(db.session, user_context)
    return await get_run_artifact_response_for_user(user, run_id)


@router.get(uri.RunStatus, status_code=HTTPStatus.OK)
async def get_run_status(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> RunnerStatus:
    """Can only fetch the status of a currently operating run.

    returns HTTP 200 on success with"""

    user = await select_user_or_raise(db.session, user_context)

    # get the run - make sure it's still "running"
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Run does not exist.")
    if run.run_status not in ACTIVE_RUN_STATUSES:
        raise HTTPException(
            status_code=HTTPStatus.GONE,
            detail=f"Run {run_id} has terminated. Please download the final artifacts for status information.",
        )

    # Connect to the pod and talk to the runner's "status" endpoint. Forward the result along
    run_resource_names = get_resource_names(run.teststack_id)
    settings = get_current_settings()
    async with ClientSession(
        base_url=run_resource_names.runner_base_url,
        timeout=ClientTimeout(settings.test_execution_comms_timeout_seconds),
    ) as s:
        try:
            return await RunnerClient.status(s)
        except Exception as exc:
            logger.error(
                f"Error fetching runner status for run {run.run_id} @ {run_resource_names.runner_base_url}.",
                exc_info=exc,
            )
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail=f"Unable to connect to run {run.run_id}'s pod to fetch status.",
            )


@router.get(uri.RunRequestList, status_code=HTTPStatus.OK)
async def get_run_request_list(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> RequestList:
    """Fetches the set of client requests that the underlying runner has collected.

    returns HTTP 200 on success with a RequestList model"""

    user = await select_user_or_raise(db.session, user_context)

    # get the run - make sure it's still "running"
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Run does not exist.")
    if run.run_status not in ACTIVE_RUN_STATUSES:
        raise HTTPException(
            status_code=HTTPStatus.GONE,
            detail=f"Run {run_id} has terminated. Please download the final artifacts for status information.",
        )

    # Connect to the pod and talk to the runner's "status" endpoint. Forward the result along
    run_resource_names = get_resource_names(run.teststack_id)
    settings = get_current_settings()
    async with ClientSession(
        base_url=run_resource_names.runner_base_url,
        timeout=ClientTimeout(settings.test_execution_comms_timeout_seconds),
    ) as s:
        try:
            return await RunnerClient.list_requests(s)
        except Exception as exc:
            logger.error(
                f"Error fetching runner request list for run {run.run_id} @ {run_resource_names.runner_base_url}.",
                exc_info=exc,
            )
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail=f"Unable to connect to run {run.run_id}'s pod to fetch request list.",
            )


@router.get(uri.RunRequest, status_code=HTTPStatus.OK)
async def get_run_request_data(
    run_id: int,
    request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> RequestData:
    """Fetches a specific client request that the underlying runner has collected. request_id can be discovered via
    get_run_request_list endpoint or from a RunnerStatus response.

    returns HTTP 200 on success with a RequestData model"""

    user = await select_user_or_raise(db.session, user_context)

    # get the run - make sure it's still "running"
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Run does not exist.")
    if run.run_status not in ACTIVE_RUN_STATUSES:
        raise HTTPException(
            status_code=HTTPStatus.GONE,
            detail=f"Run {run_id} has terminated. Please download the final artifacts for status information.",
        )

    # Connect to the pod and talk to the runner's "status" endpoint. Forward the result along
    run_resource_names = get_resource_names(run.teststack_id)
    settings = get_current_settings()
    async with ClientSession(
        base_url=run_resource_names.runner_base_url,
        timeout=ClientTimeout(settings.test_execution_comms_timeout_seconds),
    ) as s:
        try:
            return await RunnerClient.get_request(s, request_id)
        except Exception as exc:
            logger.error(
                f"Error fetching runner req {request_id} for run {run.run_id} @ {run_resource_names.runner_base_url}.",
                exc_info=exc,
            )
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail=f"Unable to connect to run {run.run_id}'s pod to fetch request {request_id}.",
            )
