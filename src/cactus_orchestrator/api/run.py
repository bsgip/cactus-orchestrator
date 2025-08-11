import logging
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Annotated

from cactus_runner.client import ClientSession, ClientTimeout, RunnerClient, RunnerClientException
from cactus_runner.models import RunnerStatus
from cactus_test_definitions import CSIPAusVersion
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.crud import (
    create_runartifact,
    insert_run_for_run_group,
    insert_run_group,
    select_active_runs_for_user,
    select_run_group_for_user,
    select_run_groups_for_user,
    select_runs_for_group,
    select_user,
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
from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User
from cactus_orchestrator.schema import (
    InitRunRequest,
    InitRunResponse,
    RunGroupRequest,
    RunGroupResponse,
    RunResponse,
    RunStatusResponse,
    StartRunResponse,
    UserContext,
)
from cactus_orchestrator.settings import CactusOrchestratorException

logger = logging.getLogger(__name__)


router = APIRouter()


def map_group_to_group_response(group: RunGroup) -> RunGroupResponse:
    return RunGroupResponse(
        run_group_id=group.run_group_id,
        name=group.name,
        csip_aus_version=group.csip_aus_version,
        created_at=group.created_at,
    )


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
    )


async def select_user_or_raise(
    session: AsyncSession,
    user_context: UserContext,
    with_aggregator_der: bool = False,
    with_aggregator_p12: bool = False,
    with_device_der: bool = False,
    with_device_p12: bool = False,
) -> User:
    user = await select_user(
        session,
        user_context,
        with_aggregator_der=with_aggregator_der,
        with_aggregator_p12=with_aggregator_p12,
        with_device_der=with_device_der,
        with_device_p12=with_device_p12,
    )

    if user is None:
        logger.error(f"Cannot find user for user context {user_context}")
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Certificate has not been registered.")
    return user


async def select_user_run_group_or_raise(
    session: AsyncSession,
    user_context: UserContext,
    run_group_id: int,
    with_aggregator_der: bool = False,
    with_aggregator_p12: bool = False,
    with_device_der: bool = False,
    with_device_p12: bool = False,
) -> tuple[User, RunGroup]:
    user = await select_user_or_raise(
        session,
        user_context,
        with_aggregator_der=with_aggregator_der,
        with_aggregator_p12=with_aggregator_p12,
        with_device_der=with_device_der,
        with_device_p12=with_device_p12,
    )

    run_group = await select_run_group_for_user(session, user.user_id, run_group_id)
    if run_group is None:
        logger.error(f"Cannot find run_group {run_group_id} for user {user.user_id}")
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail=f"Cannot find run_group {run_group_id} for user {user.user_id}"
        )

    return (user, run_group)


def ensure_certificate_valid(cert_type: str, der_data: bytes | None) -> x509.Certificate:
    if der_data is None:
        raise HTTPException(
            HTTPStatus.EXPECTATION_FAILED,
            detail=f"Your {cert_type} certificate needs to be generated before starting a test run.",
        )

    client_cert = x509.load_der_x509_certificate(der_data)
    if client_cert.not_valid_after_utc < datetime.now(timezone.utc):
        raise HTTPException(
            HTTPStatus.EXPECTATION_FAILED,
            detail=f"Your {cert_type} certificate has expired. Please regenerate your certificate and try again.",
        )
    return client_cert


@router.get("/run_group", status_code=HTTPStatus.OK)
async def get_groups_paginated(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Page[RunGroupResponse]:
    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get runs
    run_groups = await select_run_groups_for_user(db.session, user.user_id)

    if run_groups:
        resp = [map_group_to_group_response(group) for group in run_groups if group]
    else:
        resp = []
    return paginate(resp)


@router.post("/run_group", status_code=HTTPStatus.CREATED)
async def create_group(
    group_request: RunGroupRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> RunGroupResponse:

    # get user
    user = await select_user_or_raise(db.session, user_context)

    try:
        csip_aus_version = CSIPAusVersion(group_request.csip_aus_version)
    except Exception:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST, detail=f"'{group_request.csip_aus_version}' doesn't map to a known CSIPAusVersion"
        )

    # get runs
    run_group = await insert_run_group(db.session, user.user_id, csip_aus_version.value)
    await db.session.commit()
    return map_group_to_group_response(run_group)


@router.get("/run_group/{run_group_id}/run", status_code=HTTPStatus.OK)
async def get_group_runs_paginated(
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
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
    "/run_group/{run_group_id}/run",
    status_code=HTTPStatus.CREATED,
)
async def spawn_teststack_and_init_run(
    test: InitRunRequest,
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
    response: Response,
) -> InitRunResponse:
    """This endpoint sets up a test procedure as requested by client.
    Steps are:
        (1) Create a service/statefulset representing the isolated envoy test environment.
        (2) Init any state in the envoy environment.
        (3) Update the ingress with a path to the envoy environment.
    """
    # get user and the preferred certificate
    user, run_group = await select_user_run_group_or_raise(
        db.session, user_context, run_group_id, with_aggregator_der=True, with_device_der=True
    )
    if user.is_device_cert:
        client_cert = ensure_certificate_valid("Device", user.device_certificate_x509_der)
    else:
        client_cert = ensure_certificate_valid("Aggregator", user.aggregator_certificate_x509_der)

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
        db.session, run_group_id, teststack_id, test.test_procedure_id, RunStatus.provisioning, user.is_device_cert
    )

    try:
        # duplicate resources
        await clone_statefulset(template_resource_names, run_resource_names)
        await clone_service(template_resource_names, run_resource_names)

        # wait for statefulset's pod
        await wait_for_pod(run_resource_names)

        # inject initial state with either the device or aggregator cert data
        pem_encoded_cert = client_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        async with ClientSession(base_url=run_resource_names.runner_base_url, timeout=ClientTimeout(30)) as s:
            await RunnerClient.init(
                session=s,
                test_id=test.test_procedure_id,
                csip_aus_version=CSIPAusVersion(run_group.csip_aus_version),
                aggregator_certificate=None if user.is_device_cert else pem_encoded_cert,
                device_certificate=pem_encoded_cert if user.is_device_cert else None,
                subscription_domain=user.subscription_domain,
                run_id=str(run_id),
            )

        # finally, include new service in ingress rule
        await add_ingress_rule(run_resource_names)

    except (CactusOrchestratorException, RunnerClientException) as exc:
        logger.info(exc)
        await teardown_teststack(run_resource_names)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, detail="Internal Server Error")

    # commit DB changes
    await update_run_run_status(db.session, run_id, RunStatus.initialised)
    await db.session.commit()

    # set location header
    response.headers["Location"] = f"/run/{run_id}"

    return InitRunResponse(run_id=run_id, test_url=generate_envoy_dcap_uri(run_resource_names))


@router.post(
    "/run/{run_id}",
    status_code=HTTPStatus.OK,
)
async def start_run(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
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
    async with ClientSession(base_url=run_resource_names.runner_base_url, timeout=ClientTimeout(30)) as s:
        await RunnerClient.start(s)

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
    run: Run, url: str, session: AsyncSession, run_status: RunStatus, finalised_at: datetime
) -> RunArtifact | None:

    async with ClientSession(base_url=url, timeout=ClientTimeout(30)) as s:

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


@router.get("/run/{run_id}", status_code=HTTPStatus.OK)
async def get_individual_run(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
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


@router.post("/run/{run_id}/finalise", status_code=HTTPStatus.OK)
async def finalise_run_and_teardown_teststack(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:
    """Returns 200 and a binary zip stream on success. Returns 201 if the finalize succeeded but there was an error
    fetching the finalized data."""
    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    # get resource names
    run_resource_names = get_resource_names(run.teststack_id)

    # finalise
    artifact = await finalise_run(
        run,
        run_resource_names.runner_base_url,
        db.session,
        RunStatus.finalised_by_client,
        datetime.now(timezone.utc),
    )
    await db.session.commit()

    # teardown
    await teardown_teststack(run_resource_names)

    if artifact is None:
        return Response(status_code=HTTPStatus.NO_CONTENT)
    else:
        return Response(
            status_code=HTTPStatus.OK,
            content=artifact.file_data,
            media_type=f"application/{artifact.compression}",
        )


@router.get("/run/{run_id}/artifact", status_code=HTTPStatus.OK)
async def get_run_artifact(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run_with_artifact(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Run does not exist.")

    if run.run_artifact is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="RunArtifact does not exist.")

    return Response(
        content=run.run_artifact.file_data,
        media_type=f"application/{run.run_artifact.compression}",
    )


@router.get("/run/{run_id}/status", status_code=HTTPStatus.OK)
async def get_run_status(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
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
    if run.run_status not in [RunStatus.started, RunStatus.initialised]:
        raise HTTPException(
            status_code=HTTPStatus.GONE,
            detail=f"Run {run_id} has terminated. Please download the final artifacts for status information.",
        )

    # Connect to the pod and talk to the runner's "status" endpoint. Forward the result along
    run_resource_names = get_resource_names(run.teststack_id)
    async with ClientSession(base_url=run_resource_names.runner_base_url, timeout=ClientTimeout(30)) as s:
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
