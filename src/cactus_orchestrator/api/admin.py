import logging
from datetime import datetime
from http import HTTPStatus
from typing import Annotated

from cactus_runner.client import ClientSession, ClientTimeout, RunnerClient
from cactus_runner.models import RunnerStatus
from fastapi import APIRouter, Depends, Query
from fastapi.exceptions import HTTPException
from fastapi.responses import Response
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.api.procedure import test_procedure_definitions
from cactus_orchestrator.api.run import (
    map_run_to_run_response,
    select_user_or_raise,
    select_user_run_group_or_raise,
    select_user_run_with_artifact,
)
from cactus_orchestrator.api.run_group import map_group_to_group_response
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.crud import (
    ACTIVE_RUN_STATUSES,
    select_group_runs_aggregated_by_procedure,
    select_group_runs_for_procedure,
    select_run_group_counts_for_user,
    select_run_groups_by_user,
    select_run_groups_for_user,
    select_runs_for_group,
    select_user_from_run,
    select_user_from_run_group,
    select_user_run,
    select_users,
)
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.model import User
from cactus_orchestrator.schema import (
    RunGroupResponse,
    RunResponse,
    TestProcedureRunSummaryResponse,
    UserWithRunGroupsResponse,
)
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


@router.get("/admin/users", status_code=HTTPStatus.OK)
async def admin_get_users(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> Page[UserWithRunGroupsResponse]:
    run_groups_by_user = await select_run_groups_by_user(db.session)
    users = await select_users(db.session)

    resp = [
        UserWithRunGroupsResponse(
            user_id=user.user_id,
            name=user.subject_id,
            run_groups=run_groups_by_user[user.user_id] if user.user_id in run_groups_by_user else [],
        )
        for user in users
    ]

    return paginate(resp)


@router.get("/admin/procedure_runs/{run_group_id}", status_code=HTTPStatus.OK)
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
            (
                f"Failed to assume new user context ({run_group_id=},"
                f" assumed_user_context={user_context}, {original_user_context=})"
            )
        )
    (_, run_group) = await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    # Enumerate our aggregated summaries from the DB and combine them with additional metadata from the YAML definitions
    results: list[TestProcedureRunSummaryResponse] = []
    for agg in await select_group_runs_aggregated_by_procedure(db.session, run_group_id):
        definition = test_procedure_definitions.test_procedures.get(agg.test_procedure_id.value, None)
        if definition and (run_group.csip_aus_version in definition.target_versions):
            results.append(
                TestProcedureRunSummaryResponse(
                    test_procedure_id=agg.test_procedure_id,
                    description=definition.description,
                    category=definition.category,
                    classes=definition.classes,
                    run_count=agg.count,
                    latest_all_criteria_met=agg.latest_all_criteria_met,
                )
            )

    return results


@router.get("/admin/run_group", status_code=HTTPStatus.OK)
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
            (
                f"Failed to assume new user context ({run_group_id=},"
                f" assumed_user_context={user_context}, {original_user_context=})"
            )
        )
    user = await select_user_or_raise(db.session, user_context)

    # get runs
    run_groups = await select_run_groups_for_user(db.session, user.user_id)
    run_group_counts = await select_run_group_counts_for_user(db.session, [r.run_group_id for r in run_groups])

    if run_groups:
        resp = [
            map_group_to_group_response(group, run_group_counts.get(group.run_group_id, 0))
            for group in run_groups
            if group
        ]
    else:
        resp = []
    return paginate(resp)


@router.get("/admin/run/{run_id}/artifact", status_code=HTTPStatus.OK)
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
            (
                f"Failed to assume new user context ({run_id=},"
                f" assumed_user_context={user_context}, {original_user_context=})"
            )
        )
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


@router.get("/admin/procedure_runs/{run_group_id}/{test_procedure_id}", status_code=HTTPStatus.OK)
async def admin_get_runs_for_procedure_in_group(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
    run_group_id: int,
    test_procedure_id: str,
) -> Page[RunResponse]:

    # Get runs
    runs = await select_group_runs_for_procedure(db.session, run_group_id, test_procedure_id)

    if runs:
        resp = [map_run_to_run_response(run) for run in runs if run]
    else:
        resp = []
    return paginate(resp)


@router.get("/admin/run_group/{run_group_id}/run", status_code=HTTPStatus.OK)
async def admin_get_group_runs_paginated(
    run_group_id: int,
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
    finalised: bool | None = Query(default=None),
    created_after: datetime = Query(default=None),
) -> Page[RunResponse]:

    # get runs
    runs = await select_runs_for_group(db.session, run_group_id, finalised=finalised, created_at_gte=created_after)

    if runs:
        resp = [map_run_to_run_response(run) for run in runs if run]
    else:
        resp = []
    return paginate(resp)


@router.get("/admin/run/{run_id}/status", status_code=HTTPStatus.OK)
async def admin_get_run_status(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.admin_all}))],
) -> RunnerStatus:
    """Can only fetch the status of a currently operating run.

    returns HTTP 200 on success with"""

    # get user
    user_context, original_user_context = await assume_user_context_from_run(
        session=db.session, user_context=user_context, run_id=run_id
    )
    if user_context == original_user_context:
        logger.error(
            (
                f"Failed to assume new user context ({run_id=},"
                f" assumed_user_context={user_context}, {original_user_context=})"
            )
        )
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


@router.get("/admin/run/{run_id}", status_code=HTTPStatus.OK)
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
            (
                f"Failed to assume new user context ({run_id=},"
                f" assumed_user_context={user_context}, {original_user_context=})"
            )
        )
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    return map_run_to_run_response(run)
