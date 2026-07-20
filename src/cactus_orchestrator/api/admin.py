import asyncio
import dataclasses
import logging
from datetime import datetime
from http import HTTPStatus
from typing import Annotated

from cactus_runner.client import ClientSession, ClientTimeout, RunnerClient
from cactus_schema.orchestrator import (
    AdminComplianceRequestResponse,
    AdminStatsResponse,
    ComplianceRequestResponse,
    ComplianceRequestUpdateRequest,
    ComplianceRequestUser,
    ProceedResponse,
    RunGroupResponse,
    RunResponse,
    TestProcedureRunSummaryResponse,
    UserWithRunGroupsResponse,
    uri,
)
from cactus_schema.runner import RunnerStatus
from fastapi import APIRouter, Depends, Query
from fastapi.exceptions import HTTPException
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator import artifact
from cactus_orchestrator.api.common import (
    map_run_to_run_response,
    map_to_compliance_request_response,
    select_user_or_raise,
    select_user_run_group_or_raise,
    select_user_run_group_run_or_raise,
    test_procedures_by_id,
)
from cactus_orchestrator.api.run import get_run_artifact_response_for_user
from cactus_orchestrator.api.run_group import map_group_to_group_response
from cactus_orchestrator.artifact import regenerate_run_artifact
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.chart import generate_power_limit_chart
from cactus_orchestrator.crud import (
    ACTIVE_RUN_STATUSES,
    finalise_compliance_request,
    insert_compliance_generation_record,
    safe_delete_compliance_request,
    select_admin_stats,
    select_compliance_request,
    select_compliance_request_finalisation,
    select_compliance_requests,
    select_group_runs_aggregated_by_procedure,
    select_group_runs_for_procedure,
    select_run_group_counts_for_user,
    select_run_groups_by_user,
    select_run_groups_for_user,
    select_runs_for_group,
    select_user_from_run,
    select_user_from_run_group,
    select_user_run_with_artifact,
    select_users,
    update_compliance_generation_record_with_file_data,
    update_compliance_request,
)
from cactus_orchestrator.model import ComplianceRequest, User
from cactus_orchestrator.pod.models import PodResources, PodRoutes
from cactus_orchestrator.settings import get_current_settings

logger = logging.getLogger(__name__)


router = APIRouter()


async def select_user_with_run_group_or_raise(
    session: AsyncSession,
    run_group_id: int,
) -> User:

    user = await select_user_from_run_group(session=session, run_group_id=run_group_id)

    if user is None:
        logger.error(f"Cannot find user associated with run group {run_group_id}")
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail=f"Cannot find run_group {run_group_id}.")
    return user


async def select_user_with_run_or_raise(
    session: AsyncSession,
    run_id: int,
) -> User:

    user = await select_user_from_run(session=session, run_id=run_id)

    if user is None:
        logger.error(f"Cannot find user associated with run {run_id}")
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail=f"Cannot find run {run_id}.")
    return user


async def assume_user_context_from_run_group(
    session: AsyncSession, user_context: UserContext, run_group_id: int
) -> tuple[UserContext, UserContext]:
    """Assumes user context of user with run group given by run_group_id.

    User must have admin permissions to assume user context of another user.

    Args:
        session (AsyncSession): A async database session
        user_context: The user context
        run_group_id: The run group id belonging to the user who user context we will assume.

    Returns:
        A tuple of the assumed user context (with run group 'run_group_id') and the original
        user context (passed in to function).
        If the user is not an admin, the returned user contexts are the same i.e. the one passed into the function.

    Raises:
        HTTPException if no user can be found associated with the 'run_group_id'.
    """

    # user is not an admin so can't assume the user context of a different user
    if AuthPerm.admin_all not in user_context.permissions:
        return user_context, user_context

    user = await select_user_with_run_group_or_raise(
        session=session,
        run_group_id=run_group_id,
    )

    assumed_user_context = UserContext(subject_id=user.subject_id, issuer_id=user.issuer_id)
    return assumed_user_context, user_context


async def assume_user_context_from_run(
    session: AsyncSession, user_context: UserContext, run_id: int
) -> tuple[UserContext, UserContext]:
    """Assumes user context of user with run given by run_id.

    User must have admin permissions to assume user context of another user.

    Args:
        session (AsyncSession): A async database session
        user_context: The user context
        run_id: The run id belonging to the user who user context we will assume.

    Returns:
        A tuple of the assumed user context (with run 'run_id') and the original
        user context (passed in to function).
        If the user is not an admin, the returned user contexts are the same i.e. the one passed into the function.

    Raises:
        HTTPException if no user can be found associated with the 'run_id'.
    """

    # user is not an admin so can't assume the user context of a different user
    if AuthPerm.admin_all not in user_context.permissions:
        return user_context, user_context

    user = await select_user_with_run_or_raise(
        session=session,
        run_id=run_id,
    )

    assumed_user_context = UserContext(subject_id=user.subject_id, issuer_id=user.issuer_id)
    return assumed_user_context, user_context


@router.get(uri.AdminUsersList, status_code=HTTPStatus.OK)
async def admin_get_users(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> list[UserWithRunGroupsResponse]:
    run_groups_by_user = await select_run_groups_by_user(db.session)
    users = await select_users(db.session)

    settings = get_current_settings()

    resp = [
        UserWithRunGroupsResponse(
            user_id=user.user_id,
            subject_id=user.subject_id,
            name=user.user_name,
            run_groups=(
                [
                    map_group_to_group_response(
                        group=rg,
                        cactus_fqdn=settings.cactus_fqdn,
                        envoy_href=settings.envoy_prefix,
                        total_runs=0,
                    )
                    for rg in run_groups_by_user[user.user_id]
                ]
                if user.user_id in run_groups_by_user
                else []
            ),
        )
        for user in users
    ]
    return resp


@router.get(uri.AdminStats, status_code=HTTPStatus.OK)
async def admin_get_stats(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> AdminStatsResponse:
    return await select_admin_stats(db.session, test_procedures_by_id)


@router.get(uri.AdminRunGroupProceduresList, status_code=HTTPStatus.OK)
async def admin_get_procedure_run_summaries_for_group(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
    run_group_id: int,
) -> list[TestProcedureRunSummaryResponse]:
    """Will not serve summaries for test procedures outside the RunGroup csip_aus_version"""
    # Check permissions
    user_context, original_user_context = await assume_user_context_from_run_group(
        session=db.session, user_context=user_context, run_group_id=run_group_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_group_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )
    _, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    # Enumerate our aggregated summaries from the DB and combine them with additional metadata from the YAML definitions
    results: list[TestProcedureRunSummaryResponse] = []
    for agg in await select_group_runs_aggregated_by_procedure(db.session, run_group_id):
        definition = test_procedures_by_id.get(agg.test_procedure_id, None)
        if definition and (run_group.csip_aus_version in definition.target_versions):
            results.append(
                TestProcedureRunSummaryResponse(
                    test_procedure_id=agg.test_procedure_id,
                    description=definition.description,
                    category=definition.category,
                    classes=definition.classes,
                    run_count=agg.count,
                    latest_all_criteria_met=agg.latest_all_criteria_met,
                    latest_run_status=agg.latest_run_status,
                    latest_run_id=agg.latest_run_id,
                    latest_run_timestamp=agg.latest_run_timestamp,
                    immediate_start=definition.preconditions is not None and definition.preconditions.immediate_start,
                )
            )

    return results


@router.get(uri.AdminRunGroupList, status_code=HTTPStatus.OK)
async def admin_get_groups_paginated(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
    run_group_id: int | None = Query(default=None),
) -> Page[RunGroupResponse]:
    """Gets all the run groups for a user which owns 'run_group_id'.

    This is the admin equivalent to 'get_groups_paginated'.
    """
    if run_group_id is None:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="run_group_id query parameter must be supplied.")

    # get user
    user_context, original_user_context = await assume_user_context_from_run_group(
        session=db.session, user_context=user_context, run_group_id=run_group_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_group_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )
    user = await select_user_or_raise(db.session, user_context)
    settings = get_current_settings()

    # get runs
    run_groups = await select_run_groups_for_user(db.session, user.user_id)
    run_group_counts = await select_run_group_counts_for_user(db.session, [r.run_group_id for r in run_groups])

    if run_groups:
        resp = [
            map_group_to_group_response(
                group, settings.cactus_fqdn, settings.envoy_prefix, run_group_counts.get(group.run_group_id, 0)
            )
            for group in run_groups
            if group
        ]
    else:
        resp = []
    return paginate(resp)


@router.get(uri.AdminRunArtifact, status_code=HTTPStatus.OK)
async def admin_get_run_artifact(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Response:

    # get user
    user_context, original_user_context = await assume_user_context_from_run(
        session=db.session, user_context=user_context, run_id=run_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )
    user = await select_user_or_raise(db.session, user_context)

    # Get the download data
    return await get_run_artifact_response_for_user(user, run_id)


@router.get(uri.AdminRunRegenerateReport, status_code=HTTPStatus.OK)
async def admin_regenerate_report_and_get_run_artifact(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Response:

    # get user
    user_context, original_user_context = await assume_user_context_from_run(
        session=db.session, user_context=user_context, run_id=run_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )
    user = await select_user_or_raise(db.session, user_context)

    try:
        run = await select_user_run_with_artifact(db.session, user.user_id, run_id)
    except NoResultFound as err:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Run does not exist.") from err

    if run.run_artifact is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="RunArtifact does not exist.")

    if run.run_artifact.reporting_data is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="RunArtifact has no reporting data.")

    try:
        await regenerate_run_artifact(session=db.session, run=run, run_artifact=run.run_artifact)
    except ValueError as err:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail="Unable to regenerate pdf run report"
        ) from err
    await db.session.commit()

    # Get the download data
    return await get_run_artifact_response_for_user(user, run_id)


@router.get(uri.AdminRunPowerLimitChart, status_code=HTTPStatus.OK)
async def admin_get_run_power_limit_chart(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
    video_start_seconds: float | None = Query(None),
) -> Response:
    """Generates and returns a standalone HTML power limit chart for the run's envoy DB artifact (admin access)."""
    user_context, original_user_context = await assume_user_context_from_run(
        session=db.session, user_context=user_context, run_id=run_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )
    user = await select_user_or_raise(db.session, user_context)

    try:
        run = await select_user_run_with_artifact(db.session, user.user_id, run_id)
    except NoResultFound as err:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Run does not exist.") from err

    if run.run_artifact is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="RunArtifact does not exist.")

    try:
        html = await generate_power_limit_chart(run.run_artifact, video_start_seconds=video_start_seconds)
    except ValueError as err:
        logger.warning(f"power_limit_chart: generation failed for {run_id=}: {err}")
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=f"Chart generation failed: {err}") from err

    if html is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Chart unavailable: insufficient DER data in artifact.",
        )

    return Response(content=html, media_type="text/html")


@router.get(uri.AdminRunGroupProcedureRunList, status_code=HTTPStatus.OK)
async def admin_get_runs_for_procedure_in_group(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
    run_group_id: int,
    test_procedure_id: str,
) -> Page[RunResponse]:

    # Get runs
    user_context, original_user_context = await assume_user_context_from_run_group(
        session=db.session, user_context=user_context, run_group_id=run_group_id
    )
    user, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)
    runs = await select_group_runs_for_procedure(db.session, run_group_id, test_procedure_id)

    settings = get_current_settings()
    run_responses: list[RunResponse] = []
    for run in runs:
        pod_resources = PodResources.from_run(settings.podman_network, run)
        pod_routes = PodRoutes.from_run(
            settings.cactus_fqdn,
            settings.envoy_prefix,
            settings.podman_runner_port,
            pod_resources,
            run_group,
            run,
        )
        run_responses.append(map_run_to_run_response(run, pod_routes))

    return paginate(run_responses)


@router.get(uri.AdminRunGroupRunList, status_code=HTTPStatus.OK)
async def admin_get_group_runs_paginated(
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
    finalised: bool | None = Query(default=None),
    created_after: datetime = Query(default=None),  # noqa: B008
) -> Page[RunResponse]:

    # get runs
    user_context, original_user_context = await assume_user_context_from_run_group(
        session=db.session, user_context=user_context, run_group_id=run_group_id
    )
    user, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)
    runs = await select_runs_for_group(db.session, run_group_id, finalised=finalised, created_at_gte=created_after)

    settings = get_current_settings()
    run_responses: list[RunResponse] = []
    for run in runs:
        pod_resources = PodResources.from_run(settings.podman_network, run)
        pod_routes = PodRoutes.from_run(
            settings.cactus_fqdn,
            settings.envoy_prefix,
            settings.podman_runner_port,
            pod_resources,
            run_group,
            run,
        )
        run_responses.append(map_run_to_run_response(run, pod_routes))
    return paginate(run_responses)


@router.get(uri.AdminRunStatus, status_code=HTTPStatus.OK)
async def admin_get_run_status(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> RunnerStatus:
    """Can only fetch the status of a currently operating run.

    returns HTTP 200 on success with"""

    # assume user
    user_context, original_user_context = await assume_user_context_from_run(
        session=db.session, user_context=user_context, run_id=run_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )

    # get the run - make sure it's still "running"
    _, run_group, run = await select_user_run_group_run_or_raise(db.session, user_context, run_id)
    if run.run_status not in ACTIVE_RUN_STATUSES:
        raise HTTPException(
            status_code=HTTPStatus.GONE,
            detail=f"Run {run_id} has terminated. Please download the final artifacts for status information.",
        )

    # Connect to the pod and talk to the runner's "status" endpoint. Forward the result along
    settings = get_current_settings()
    pod_resources = PodResources.from_run(settings.podman_network, run)
    pod_routes = PodRoutes.from_run(
        settings.cactus_fqdn, settings.envoy_prefix, settings.podman_runner_port, pod_resources, run_group, run
    )
    async with ClientSession(
        base_url=pod_routes.internal_base_url,
        timeout=ClientTimeout(settings.comms_timeout_seconds),
    ) as s:
        try:
            return await RunnerClient.status(s)
        except Exception as err:
            logger.error(
                f"Error fetching runner status for run {run.run_id} @ {pod_routes.internal_base_url}.",
            )
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail=f"Unable to connect to run {run.run_id}'s pod to fetch status.",
            ) from err


@router.get(uri.AdminRunProceed, status_code=HTTPStatus.OK)
async def admin_proceed_proxy(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> ProceedResponse:
    """Forwards the proceed request to the appropriate runner instance on behalf of the run's owner."""

    user_context, original_user_context = await assume_user_context_from_run(
        session=db.session, user_context=user_context, run_id=run_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )
    _, run_group, run = await select_user_run_group_run_or_raise(db.session, user_context, run_id)
    if run.run_status not in ACTIVE_RUN_STATUSES:
        raise HTTPException(
            status_code=HTTPStatus.GONE, detail=f"Run {run_id} has terminated. Unable to send proceed signal."
        )

    settings = get_current_settings()
    pod_resources = PodResources.from_run(settings.podman_network, run)
    pod_routes = PodRoutes.from_run(
        settings.cactus_fqdn, settings.envoy_prefix, settings.podman_runner_port, pod_resources, run_group, run
    )
    async with ClientSession(
        base_url=pod_routes.internal_base_url,
        timeout=ClientTimeout(settings.comms_timeout_seconds),
    ) as s:
        try:
            return await RunnerClient.proceed(s)
        except Exception as err:
            msg = f"Error sending proceed to run {run.run_id}."
            logger.error(msg)
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=msg) from err


@router.get(uri.AdminRun, status_code=HTTPStatus.OK)
async def admin_get_individual_run(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> RunResponse:

    # get user
    user_context, original_user_context = await assume_user_context_from_run(
        session=db.session, user_context=user_context, run_id=run_id
    )
    if user_context == original_user_context:
        logger.error(
            f"Failed to assume new user context ({run_id=},"
            f" assumed_user_context={user_context}, {original_user_context=})"
        )
    _, run_group, run = await select_user_run_group_run_or_raise(db.session, user_context, run_id)
    settings = get_current_settings()
    pod_resources = PodResources.from_run(settings.podman_network, run)
    pod_routes = PodRoutes.from_run(
        settings.cactus_fqdn, settings.envoy_prefix, settings.podman_runner_port, pod_resources, run_group, run
    )

    return map_run_to_run_response(run, pod_routes)


@router.get(uri.AdminRunGroupCompliance, status_code=HTTPStatus.OK)
async def admin_get_group_run_compliance_artifact(
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Response:
    """Generates the compliance report for the run group 'run_group_id'."""

    requester = await select_user_or_raise(db.session, user_context)
    requester_id = requester.user_id

    # Add the generation record to the database so we can pass the compliance_record_id during report generation
    try:
        compliance_record = await insert_compliance_generation_record(
            session=db.session, run_group_id=run_group_id, requester_id=requester_id
        )
    except Exception as err:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Unable to insert ComplianceRecord for {run_group_id=} and {requester_id=}",
        ) from err

    # Generate compliance report
    try:
        run_group_artifact = await artifact.generate_run_group_artifact(
            session=db.session, run_group_id=run_group_id, requester=requester, compliance_record=compliance_record
        )
    except NoResultFound as err:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"Run group {run_group_id} does not exist."
        ) from err

    if run_group_artifact is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="RunGroupArtifact does not exist.")

    # Update the compliance record to include pdf data
    try:
        await update_compliance_generation_record_with_file_data(
            db.session, compliance_record=compliance_record, file_data=run_group_artifact.file_data
        )
    except Exception as err:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=(
                f"Unable to update ComplianceRecord with compliance file data for {run_group_id=} and {requester_id=}"
            ),
        ) from err

    await db.session.commit()

    return Response(
        content=run_group_artifact.file_data,
        media_type=run_group_artifact.mime_type,
    )


async def map_to_admin_compliance_request_response(request: ComplianceRequest) -> AdminComplianceRequestResponse:

    def map_to_user(user: User) -> ComplianceRequestUser:
        return ComplianceRequestUser(
            user_id=user.user_id,
            subject_id=user.subject_id,
            issuer_id=user.issuer_id,
            user_name=user.user_name,
        )

    return AdminComplianceRequestResponse(
        compliance_request_id=request.compliance_request_id,
        created_at=request.created_at,
        created_by=request.created_by,
        created_by_user=map_to_user(request.created_by_user),
        updated_at=request.updated_at,
        updated_by=request.updated_by,
        updated_by_user=map_to_user(request.updated_by_user),
        status=request.status,
        classes={c.compliance_class for c in request.classes},
        runs={r.compliance_run_id for r in request.runs},
        csip_aus_version=request.csip_aus_version,
        witnessed_at=request.witnessed_at,
        der_brand=request.der_brand,
        der_oem=request.der_oem,
        der_series=request.der_series,
        der_representative_models=request.der_representative_models,
        software_client_type=request.software_client_type,
        software_client_providers=request.software_client_providers,
        software_client_versions=request.software_client_versions,
        onsite_hardware_details=request.onsite_hardware_details,
    )


@router.get(uri.AdminComplianceRequestList, status_code=HTTPStatus.OK)
async def admin_get_compliance_requests_paginated(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Page[AdminComplianceRequestResponse]:
    requests = await select_compliance_requests(session=db.session)

    if requests:
        awaitables = [map_to_admin_compliance_request_response(r) for r in requests]
        resp = await asyncio.gather(*awaitables)
    else:
        resp = []
    return paginate(resp)


@router.get(uri.AdminComplianceRequest, status_code=HTTPStatus.OK)
async def admin_get_compliance_request(
    compliance_request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> ComplianceRequestResponse | None:
    try:
        compliance_request = await select_compliance_request(
            session=db.session, compliance_request_id=compliance_request_id
        )
    except NoResultFound as err:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"Compliance request {compliance_request_id} does not exist."
        ) from err

    response = await map_to_compliance_request_response(request=compliance_request)

    return response


@router.put(uri.AdminComplianceRequest, status_code=HTTPStatus.OK)
async def admin_update_compliance_request(
    compliance_request_id: int,
    body: ComplianceRequestUpdateRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> ComplianceRequestResponse:
    # Get admin user
    admin = await select_user_or_raise(db.session, user_context)
    updated_by = admin.user_id

    # get compliance request
    try:
        request = await select_compliance_request(
            session=db.session,
            compliance_request_id=compliance_request_id,
        )
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"Compliance request {compliance_request_id} does not exist."
        ) from exc

    # Determine which parameters to update (these have a value that isn't None)
    params = {
        field.name: getattr(body, field.name)
        for field in dataclasses.fields(body)
        if getattr(body, field.name) is not None
    }

    await update_compliance_request(session=db.session, updated_by=updated_by, compliance_request=request, **params)

    await db.session.commit()
    return await map_to_compliance_request_response(request)


@router.delete(uri.AdminComplianceRequest, status_code=HTTPStatus.OK)
async def admin_delete_compliance_request_endpoint(
    compliance_request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Response:

    # get compliance request
    try:
        request = await select_compliance_request(
            session=db.session,
            compliance_request_id=compliance_request_id,
        )
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found") from exc

    try:
        request_deletable = await safe_delete_compliance_request(session=db.session, compliance_request=request)
    except Exception as exc:
        logger.debug(exc)
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail="Failed to delete compliance request"
        ) from exc

    if not request_deletable:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Compliance Request has been finalised. Unable to delete."
        )

    await db.session.commit()
    return Response(status_code=HTTPStatus.OK)


@router.get(uri.AdminComplianceRequestArtifact, status_code=HTTPStatus.OK)
async def admin_fetch_compliance_request_artifact(
    compliance_request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Response:
    compliance_request_finalisation = await select_compliance_request_finalisation(
        session=db.session, compliance_request_id=compliance_request_id
    )

    if compliance_request_finalisation is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    return Response(
        status_code=HTTPStatus.OK,
        content=compliance_request_finalisation.file_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ComplianceReport-{compliance_request_id}.pdf"},
    )


@router.post(uri.AdminComplianceRequestArtifact, status_code=HTTPStatus.OK)
async def admin_finalise_compliance_request(
    compliance_request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Response:
    """finalise the compliance request

    - Generate compliance report
    - Update compliance request with compliance report data and set status to finalised

    Note: It is possible to finalise an already finalised compliance request without error; this allows for the
    regeneration of compliance reports.
    """

    # Fetch user requesting finalisation
    requester = await select_user_or_raise(db.session, user_context)
    requester_id = requester.user_id

    # Fetch compliance request
    try:
        compliance_request = await select_compliance_request(
            session=db.session, compliance_request_id=compliance_request_id, include_users=True
        )
    except Exception as err:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Unable to find ComplianceRequest {compliance_request_id=}",
        ) from err

    # Generate compliance report
    try:
        compliance_artifact = await artifact.generate_compliance_artifact(
            requester=requester,
            compliance_request=compliance_request,
        )
    except NoResultFound as err:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="TODO ERROR MESSAGE") from err

    if compliance_artifact is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Compliance Artifact does not exist.")

    # Update the compliance record and create finalisation record which includes the pdf data
    try:
        await finalise_compliance_request(
            db.session,
            update_by=requester_id,
            compliance_request=compliance_request,
            file_data=compliance_artifact.file_data,
        )
    except Exception as err:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=(f"Unable to update ComplianceRecord with compliance file data for {compliance_request_id=}"),
        ) from err

    await db.session.commit()

    return Response(
        status_code=HTTPStatus.OK,
        content=compliance_artifact.file_data,
        media_type=compliance_artifact.mime_type,
        headers={"Content-Disposition": f"attachment; filename=ComplianceReport-{compliance_request_id}.pdf"},
    )
