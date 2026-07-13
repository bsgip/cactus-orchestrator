import logging
from http import HTTPStatus

from cactus_schema.orchestrator import PlaylistRunInfo, RunResponse, RunStatusResponse
from cactus_schema.orchestrator.schema import ComplianceRequestResponse
from cactus_test_definitions.client.test_procedures import TestProcedure, TestProcedureId
from envoy_schema.server.schema.uri import DeviceCapabilityUri
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.auth import UserContext
from cactus_orchestrator.crud import (
    insert_user,
    select_run_group_for_user,
    select_run_groups_for_user,
    select_run_with_run_group_for_user,
    select_user,
)
from cactus_orchestrator.model import ComplianceRequest, Run, RunGroup, RunStatus, User
from cactus_orchestrator.pod.models import PodRoutes
from cactus_orchestrator.procedures import get_filtered_test_procedures

logger = logging.getLogger(__name__)


test_procedures_by_id: dict[TestProcedureId, TestProcedure] = get_filtered_test_procedures()


def envoy_dcap_uri(routes: PodRoutes) -> str:
    return envoy_dcap_uri_for_host(routes.external_host, routes.href_prefix)


def envoy_dcap_uri_for_host(external_host: str, envoy_href_prefix: str) -> str:
    return f"https://{external_host}{envoy_href_prefix}{DeviceCapabilityUri}"


def map_run_status_to_run_status_response(run_status: RunStatus) -> RunStatusResponse:
    status = RunStatusResponse.finalised
    if run_status == RunStatus.initialised:
        status = RunStatusResponse.initialised
    elif run_status == RunStatus.started:
        status = RunStatusResponse.started
    elif run_status == RunStatus.provisioning:
        status = RunStatusResponse.provisioning
    elif run_status == RunStatus.skipped:
        status = RunStatusResponse.skipped
    return status


def map_run_to_run_response(
    run: Run, pod_routes: PodRoutes, playlist_runs: list[PlaylistRunInfo] | None = None
) -> RunResponse:
    status = map_run_status_to_run_status_response(run.run_status)
    try:
        definition = test_procedures_by_id.get(TestProcedureId(run.testprocedure_id), None)
    except ValueError:
        definition = None

    return RunResponse(
        run_id=run.run_id,
        test_procedure_id=run.testprocedure_id,
        test_url=envoy_dcap_uri(pod_routes),
        status=status,
        all_criteria_met=run.all_criteria_met,
        created_at=run.created_at,
        finalised_at=run.finalised_at,
        is_device_cert=run.is_device_cert,
        has_artifacts=run.run_artifact_id is not None,
        playlist_execution_id=run.playlist_execution_id,
        playlist_order=run.playlist_order,
        playlist_runs=playlist_runs,
        classes=definition.classes if definition else None,
        immediate_start=bool(definition and definition.preconditions and definition.preconditions.immediate_start),
    )


async def map_to_compliance_request_response(request: ComplianceRequest) -> ComplianceRequestResponse:
    return ComplianceRequestResponse(
        compliance_request_id=request.compliance_request_id,
        created_at=request.created_at,
        created_by=request.created_by,
        updated_at=request.updated_at,
        updated_by=request.updated_by,
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


async def select_user_or_create(session: AsyncSession, user_context: UserContext) -> User:
    """Fetches the user associated with user_context - creating one as required."""
    user = await select_user(session, user_context)
    if user is not None:
        return user

    user = await insert_user(session, user_context)
    logger.info(f"Created new user {user.user_id} for user context {user_context}")
    return user


async def select_user_or_raise(
    session: AsyncSession,
    user_context: UserContext,
) -> User:
    """Selects a user for the specific user context or raises a HTTPException if none can be found"""
    user = await select_user(session, user_context)

    if user is None:
        logger.error(f"Cannot find user for user context {user_context}")
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Certificate has not been registered.")
    return user


async def select_user_run_group_or_raise(
    session: AsyncSession,
    user_context: UserContext,
    run_group_id: int,
    with_cert: bool = False,
    for_update: bool = False,
) -> tuple[User, RunGroup]:
    """Selects a user for the specific user context AND their associated run_group_id or raises a HTTPException if none
    can be found.

    Can optionally include deferred certificate values on the RunGroup. Set for_update to lock the run_group row for
    the duration of the transaction (used by certificate generation to serialise the certificate_id counter)."""
    user = await select_user_or_raise(
        session,
        user_context,
    )

    run_group = await select_run_group_for_user(
        session, user.user_id, run_group_id, with_cert=with_cert, for_update=for_update
    )
    if run_group is None:
        logger.error(f"Cannot find run_group {run_group_id} for user {user.user_id}")
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail=f"Cannot find run_group {run_group_id} for user {user.user_id}"
        )

    return (user, run_group)


async def select_user_run_group_run_or_raise(
    session: AsyncSession, user_context: UserContext, run_id: int, with_cert: bool = False, with_artifact: bool = False
) -> tuple[User, RunGroup, Run]:
    """Selects a user for the specific user context AND their associated run + parent RunGroup or raises a HTTPException
    if none can be found.

    Can optionally include deferred certificate values on the RunGroup"""
    user = await select_user_or_raise(
        session,
        user_context,
    )

    run = await select_run_with_run_group_for_user(session, user.user_id, run_id, with_cert, with_artifact)
    if run is None:
        logger.error(f"Cannot find run {run_id} for user {user.user_id}")
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Cannot find run {run_id} for user {user.user_id}",
        )

    return (user, run.run_group, run)


async def select_user_run_groups_or_raise(
    session: AsyncSession, user_context: UserContext, for_update: bool = False
) -> tuple[User, list[RunGroup]]:
    """Selects a user for the specific user context AND their associated run_groups.

    Set for_update to lock the run_group rows for the duration of the transaction (used by certificate generation to
    serialise the certificate_id counter). Raises if the user not found."""

    user = await select_user_or_raise(session, user_context)

    run_groups = await select_run_groups_for_user(session, user.user_id, for_update=for_update)

    if not run_groups:
        logger.error(f"No run groups found for user {user.user_id}")
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail=f"Cannot find any run groups for user {user.user_id}"
        )

    return (user, list(run_groups))
