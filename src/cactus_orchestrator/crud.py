from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cactus_schema.orchestrator import AdminStatsResponse
from cactus_test_definitions import CSIPAusVersion
from cactus_test_definitions.client import TestProcedureId
from sqlalchemy import String, and_, case, cast, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload, undefer

from cactus_orchestrator.auth import UserContext
from cactus_orchestrator.model import (
    ComplianceRecord,
    ComplianceRequest,
    ComplianceRequestClass,
    ComplianceRequestFinalisation,
    ComplianceRequestRun,
    ComplianceRequestStatus,
    Run,
    RunArtifact,
    RunGroup,
    RunReportGeneration,
    RunStatus,
    User,
)

ACTIVE_RUN_STATUSES: set[RunStatus] = {RunStatus.provisioning, RunStatus.started, RunStatus.initialised}
FINALISED_RUN_STATUSES: set[RunStatus] = {
    RunStatus.finalised_by_client,
    RunStatus.finalised_by_timeout,
    RunStatus.terminated,
    RunStatus.skipped,
}


async def insert_run_group(session: AsyncSession, user_id: int, csip_aus_version: str, is_static_uri: bool) -> RunGroup:
    """Inserts a new RunGroup with the specified csip_aus_version. Returns the inserted RunGroup."""

    new_group = RunGroup(
        name="New Group", csip_aus_version=csip_aus_version, user_id=user_id, is_static_uri=is_static_uri
    )
    session.add(new_group)
    await session.flush()
    return new_group


async def insert_user(session: AsyncSession, user_context: UserContext) -> User:
    """Inserts a new user with no certificate details and default config. Returns the new User ID. Raises exceptions
    if a user with the same user_context already exists in the database."""

    user = User(
        subject_id=user_context.subject_id,
        issuer_id=user_context.issuer_id,
        run_groups=[
            RunGroup(name="Default Group", csip_aus_version=CSIPAusVersion.RELEASE_1_2.value, is_static_uri=True)
        ],
    )
    session.add(user)
    await session.flush()

    new_user = await select_user(session, user_context)
    if new_user is None:
        raise Exception(f"Unable to insert new user for user_context {user_context}")

    return new_user


async def select_user(session: AsyncSession, user_context: UserContext) -> User | None:

    stmt = select(User).where(
        and_(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
    )

    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def select_user_from_run_group(
    session: AsyncSession,
    run_group_id: int,
) -> User | None:

    rg_res = await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))
    run_group = rg_res.scalar_one_or_none()

    if not run_group:
        return None

    res = await session.execute(select(User).where(User.user_id == run_group.user_id))
    return res.scalar_one_or_none()


async def select_user_from_run(session: AsyncSession, run_id: int) -> User | None:

    run_res = await session.execute(select(Run).where(Run.run_id == run_id))
    run = run_res.scalar_one_or_none()

    if not run:
        return None

    return await select_user_from_run_group(session=session, run_group_id=run.run_group_id)


async def insert_run_for_run_group(
    session: AsyncSession,
    run_group_id: int,
    testprocedure_id: str,
    run_status: RunStatus,
    is_device_cert: bool,
) -> Run:
    run = Run(
        run_group_id=run_group_id,
        pod_name=None,
        testprocedure_id=testprocedure_id,
        run_status=run_status,
        is_device_cert=is_device_cert,
    )
    session.add(run)
    await session.flush()
    return run


async def select_run_groups_by_user(session: AsyncSession) -> dict[int, list[RunGroup]]:
    """Returns all run groups associated with each user, keyed by their user_id"""
    stmt = select(RunGroup)
    result = await session.execute(stmt)
    run_groups_by_user = defaultdict(list)
    for run_group in result.scalars().all():
        run_groups_by_user[run_group.user_id].append(run_group)
    return dict(run_groups_by_user)


async def select_users(session: AsyncSession) -> Sequence[User]:
    result = await session.execute(select(User).order_by(User.user_id))
    return result.scalars().all()


async def select_run_groups_for_user(
    session: AsyncSession, user_id: int, for_update: bool = False
) -> Sequence[RunGroup]:
    stmt = select(RunGroup).where(RunGroup.user_id == user_id).order_by(RunGroup.run_group_id)
    if for_update:
        # Lock the rows so concurrent certificate generation serialises on certificate_id
        stmt = stmt.with_for_update()
    resp = await session.execute(stmt)
    return resp.scalars().all()


async def update_user_name(session: AsyncSession, user_id: int, user_name: str) -> None:
    stmt = update(User).where(User.user_id == user_id).values(user_name=user_name)
    await session.execute(stmt)


async def select_run_group_counts_for_user(session: AsyncSession, run_group_ids: list[int]) -> dict[int, int]:
    """Returns a dictionary of run counts, keyed by run group id for all RunGroups owned by user_id."""
    resp = await session.execute(
        select(Run.run_group_id, func.count()).group_by(Run.run_group_id).where(Run.run_group_id.in_(run_group_ids))
    )
    return dict(resp.tuples().all())


async def select_run_group_for_user(
    session: AsyncSession, user_id: int, run_group_id: int, with_cert: bool = False, for_update: bool = False
) -> RunGroup | None:
    stmt = select(RunGroup).where((RunGroup.user_id == user_id) & (RunGroup.run_group_id == run_group_id)).limit(1)
    if with_cert:
        stmt = stmt.options(undefer(RunGroup.certificate_pem))
    if for_update:
        # Lock the row so concurrent certificate generation serialises on certificate_id
        stmt = stmt.with_for_update()

    resp = await session.execute(stmt)
    return resp.scalar_one_or_none()


async def select_run_with_run_group_for_user(
    session: AsyncSession, user_id: int, run_id: int, with_cert: bool = False, with_artifact: bool = False
) -> Run | None:
    """Selects a Run underneath a specific user_id with the parent RunGroup relationship populated."""

    stmt = select(Run).join(RunGroup).where((Run.run_id == run_id) & (RunGroup.user_id == user_id))

    if with_artifact:
        stmt = stmt.options(joinedload(Run.run_artifact))

    if with_cert:
        stmt = stmt.options(selectinload(Run.run_group).undefer(RunGroup.certificate_pem))
    else:
        stmt = stmt.options(selectinload(Run.run_group))

    resp = await session.execute(stmt)
    return resp.scalar_one_or_none()


async def delete_runs(session: AsyncSession, runs: Sequence[Run]) -> None:
    run_artifact_ids = [r.run_artifact_id for r in runs if r.run_artifact_id is not None]
    for run in runs:
        await session.delete(run)
    if run_artifact_ids:
        await session.execute(delete(RunArtifact).where(RunArtifact.run_artifact_id.in_(run_artifact_ids)))


async def select_run_for_group(session: AsyncSession, run_group_id: int, run_id: int) -> Run | None:
    stmt = select(Run).where((Run.run_id == run_id) & (Run.run_group_id == run_group_id)).limit(1)
    resp = await session.execute(stmt)
    return resp.scalar_one_or_none()


async def select_runs_for_group(
    session: AsyncSession, run_group_id: int, finalised: bool | None, created_at_gte: datetime | None
) -> Sequence[Run]:
    # runs statement
    stmt = select(Run).where(Run.run_group_id == run_group_id).order_by(Run.run_id.desc())
    filters = []
    if created_at_gte is not None:
        filters.append(Run.created_at >= created_at_gte)

    if finalised is True:
        filters.append(Run.run_status.in_(FINALISED_RUN_STATUSES))
    elif finalised is False:
        filters.append(Run.run_status.in_(ACTIVE_RUN_STATUSES))
        # Exclude initialised runs that are part of a playlist (not yet active)
        # Keep single runs and truly active playlist runs (provisioning/started)
        filters.append((Run.run_status != RunStatus.initialised) | (Run.playlist_execution_id == None))  # noqa: E711

    if filters:
        stmt = stmt.where(and_(*filters))

    resp = await session.execute(stmt)
    return resp.scalars().all()


async def select_active_runs_for_user(session: AsyncSession, user_id: int) -> Sequence[Run]:
    """Fetches all runs for a user that are in non finalised state (across all RunGroups).

    Will return RunGroup as an include"""

    stmt = (
        select(Run)
        .join(RunGroup)
        .where(RunGroup.user_id == user_id)
        .where(Run.run_status.in_(ACTIVE_RUN_STATUSES))
        # Exclude initialised runs that are part of a playlist (not yet active)
        .where((Run.run_status != RunStatus.initialised) | (Run.playlist_execution_id == None))  # noqa: E711
        .options(selectinload(Run.run_group))
        .order_by(Run.created_at.desc())
    )

    resp = await session.execute(stmt)
    return resp.scalars().all()


async def select_passed_runs_for_user(session: AsyncSession, user_id: int) -> Sequence[Run]:
    """Fetches all runs for a user (across all RunGroups) that are in a finalised state AND have met all criteria.

    Will return RunGroup as an include"""
    stmt = (
        select(Run)
        .join(RunGroup)
        .where(RunGroup.user_id == user_id)
        .where(Run.run_status.in_(FINALISED_RUN_STATUSES))
        .where(Run.all_criteria_met == True)  # noqa: E712
        .options(selectinload(Run.run_group))
        .order_by(Run.run_id.desc())
    )

    resp = await session.execute(stmt)
    return resp.scalars().all()


async def select_nonfinalised_runs(session: AsyncSession) -> Sequence[Run]:
    """Will include RunGroup relationship"""
    stmt = select(Run).where(Run.run_status.in_(ACTIVE_RUN_STATUSES)).options(selectinload(Run.run_group))
    resp = await session.execute(stmt)
    return resp.scalars().all()


async def update_run_run_status(
    session: AsyncSession, run_id: int, run_status: RunStatus, finalised_at: datetime | None = None
) -> None:
    stmt = update(Run).where(Run.run_id == run_id).values(run_status=run_status, finalised_at=finalised_at)
    await session.execute(stmt)


async def create_runartifact(
    session: AsyncSession,
    compression: str,
    file_data: bytes,
    reporting_data: str | None,
    reporting_data_version: int | None,
) -> RunArtifact:
    runartifact = RunArtifact(
        compression=compression, file_data=file_data, reporting_data=reporting_data, version=reporting_data_version
    )
    session.add(runartifact)
    await session.flush()
    return runartifact


async def update_runartifact_with_file_data(session: AsyncSession, run_artifact: RunArtifact, file_data: bytes) -> None:
    run_artifact.file_data = file_data
    await session.flush()


async def update_run_with_runartifact_and_finalise(
    session: AsyncSession,
    run: Run,
    run_artifact_id: int | None,
    run_status: RunStatus,
    finalised_at: datetime,
    all_criteria_met: bool | None,
) -> None:
    run.run_artifact_id = run_artifact_id
    run.finalised_at = finalised_at
    run.run_status = run_status
    run.all_criteria_met = all_criteria_met
    await session.flush()


async def create_run_report_generation_record(session: AsyncSession, run_artifact_id: int) -> RunReportGeneration:
    run_report_generation_record = RunReportGeneration(run_artifact_id=run_artifact_id)
    session.add(run_report_generation_record)
    await session.flush()
    return run_report_generation_record


async def select_user_run(session: AsyncSession, user_id: int, run_id: int) -> Run:
    """fetches a run_id but scoped to a specific user. If the Run DNE / doesn't belong to user_id - this will
    raise a NoResultFound exception"""
    stmt = (
        select(Run)
        .join(RunGroup)
        .options(selectinload(Run.run_group))
        .where(
            and_(
                Run.run_id == run_id,
                RunGroup.user_id == user_id,
            )
        )
    )

    resp = await session.execute(stmt)

    return resp.scalar_one()


async def select_user_run_with_artifact(session: AsyncSession, user_id: int, run_id: int) -> Run:
    stmt = (
        select(Run)
        .join(RunGroup)
        .where(
            and_(
                Run.run_id == run_id,
                RunGroup.user_id == user_id,
            )
        )
        .options(joinedload(Run.run_artifact))
        .options(selectinload(Run.run_group))
    )

    resp = await session.execute(stmt)

    return resp.scalar_one()


async def select_user_runs_with_artifacts(session: AsyncSession, user_id: int, run_ids: list[int]) -> Sequence[Run]:
    stmt = (
        select(Run)
        .join(RunGroup)
        .where(
            and_(
                Run.run_id.in_(run_ids),
                RunGroup.user_id == user_id,
            )
        )
        .options(joinedload(Run.run_artifact))
        .options(selectinload(Run.run_group))
    )

    resp = await session.execute(stmt)

    return resp.unique().scalars().all()


@dataclass
class ProcedureRunAggregated:
    test_procedure_id: TestProcedureId
    count: int  # Count of runs for this test procedure
    latest_all_criteria_met: bool | None  # Value for all_criteria_met of the most recent Run
    latest_run_status: int | None
    latest_run_id: int | None
    latest_run_timestamp: datetime | None


async def select_group_runs_aggregated_by_procedure(
    session: AsyncSession, run_group_id: int
) -> list[ProcedureRunAggregated]:
    """Generates a ProcedureRunAggregated for each TestProcedureId. This will aggregate all runs under each
    TestProcedure and provide top level summary information."""

    # Do the count first
    count_resp = await session.execute(
        select(Run.testprocedure_id, func.count())
        .select_from(Run)
        .where(
            Run.run_group_id == run_group_id,
        )
        .group_by(Run.testprocedure_id)
    )
    raw_counts = dict(r._tuple() for r in count_resp.all())

    # Do the "distinct on" query for the latest runs by type
    stmt = (
        select(Run.testprocedure_id, Run.all_criteria_met, Run.run_status, Run.run_id, Run.finalised_at)
        .distinct(Run.testprocedure_id)
        .order_by(Run.testprocedure_id, Run.run_id.desc())
        .where(Run.run_group_id == run_group_id)
    )
    distinct_resp = await session.execute(stmt)
    raw_criteria = {r._tuple()[0]: r._tuple() for r in distinct_resp.all()}

    return [
        ProcedureRunAggregated(
            test_procedure_id=tp,
            count=raw_counts.get(tp.value, 0),
            latest_all_criteria_met=raw_criteria[tp.value][1] if tp.value in raw_criteria else None,
            latest_run_status=raw_criteria[tp.value][2] if tp.value in raw_criteria else None,
            latest_run_id=raw_criteria[tp.value][3] if tp.value in raw_criteria else None,
            latest_run_timestamp=raw_criteria[tp.value][4] if tp.value in raw_criteria else None,
        )
        for tp in TestProcedureId
    ]


async def select_group_runs_for_procedure(
    session: AsyncSession, run_group_id: int, test_procedure_id: str
) -> Sequence[Run]:
    """Selects all RunGroup runs that exist under a test procedure. Will not include deferred data. Returns runs
    returned in run_id descending order (most recent first)."""

    # Fetch all runs
    resp = await session.execute(
        select(Run)
        .where(and_(Run.run_group_id == run_group_id, Run.testprocedure_id == test_procedure_id))
        .order_by(Run.run_id.desc())
    )

    return resp.scalars().all()


async def insert_compliance_generation_record(
    session: AsyncSession, run_group_id: int, requester_id: int
) -> ComplianceRecord:
    compliance_record = ComplianceRecord(run_group_id=run_group_id, requester_id=requester_id)

    session.add(compliance_record)
    await session.flush()

    return compliance_record


async def update_compliance_generation_record_with_file_data(
    session: AsyncSession, compliance_record: ComplianceRecord, file_data: bytes
) -> None:
    compliance_record.file_data = file_data
    await session.flush()


async def finalise_compliance_request(
    session: AsyncSession, update_by: int, compliance_request: ComplianceRequest, file_data: bytes
) -> None:
    finalisation_timestamp = datetime.now(UTC)

    compliance_request.updated_by = update_by
    compliance_request.updated_at = finalisation_timestamp
    compliance_request.status = ComplianceRequestStatus.FINALISED

    await insert_compliance_request_finalisation(
        session=session,
        compliance_request_id=compliance_request.compliance_request_id,
        created_at=finalisation_timestamp,
        created_by=update_by,
        file_data=file_data,
    )

    await session.flush()


async def select_compliance_request(
    session: AsyncSession,
    compliance_request_id: int,
    include_users: bool = False,
) -> ComplianceRequest:
    stmt = select(ComplianceRequest).where(ComplianceRequest.compliance_request_id == compliance_request_id)
    stmt = stmt.options(selectinload(ComplianceRequest.classes))
    stmt = stmt.options(selectinload(ComplianceRequest.runs))
    if include_users:
        stmt = stmt.options(joinedload(ComplianceRequest.created_by_user))
        stmt = stmt.options(joinedload(ComplianceRequest.updated_by_user))

    result = await session.execute(stmt)
    return result.scalar_one()


async def select_user_compliance_request(
    session: AsyncSession,
    user_id: int,
    compliance_request_id: int,
) -> ComplianceRequest:
    stmt = select(ComplianceRequest).where(
        ComplianceRequest.compliance_request_id == compliance_request_id, ComplianceRequest.created_by == user_id
    )
    stmt = stmt.options(selectinload(ComplianceRequest.classes))
    stmt = stmt.options(selectinload(ComplianceRequest.runs))

    result = await session.execute(stmt)
    return result.scalar_one()


async def select_user_compliance_requests(session: AsyncSession, user_id: int) -> Sequence[ComplianceRequest]:
    """Get compliance requests for user_id ordered by creation date DESCENDING"""
    stmt = (
        select(ComplianceRequest)
        .where(ComplianceRequest.created_by == user_id)
        .order_by(ComplianceRequest.created_at.desc())
    )
    stmt = stmt.options(selectinload(ComplianceRequest.classes))
    stmt = stmt.options(selectinload(ComplianceRequest.runs))
    result = await session.execute(stmt)
    return result.scalars().all()


async def select_compliance_requests(session: AsyncSession) -> Sequence[ComplianceRequest]:
    """Get compliance requests for all users ordered by creation date DESCENDING"""
    stmt = select(ComplianceRequest).order_by(ComplianceRequest.created_at.desc())
    stmt = stmt.options(selectinload(ComplianceRequest.classes))
    stmt = stmt.options(selectinload(ComplianceRequest.runs))
    stmt = stmt.options(joinedload(ComplianceRequest.created_by_user))
    stmt = stmt.options(joinedload(ComplianceRequest.updated_by_user))
    result = await session.execute(stmt)
    return result.scalars().all()


async def insert_compliance_request(
    session: AsyncSession,
    created_by: int,
    csip_aus_version: str,
    witnessed_at: datetime,
    classes: set[str],
    runs: set[int],
    der_brand: str,
    der_oem: str,
    der_series: str,
    der_representative_models: str,
    software_client_type: str,
    software_client_providers: str,
    software_client_versions: str,
    onsite_hardware_details: str,
) -> ComplianceRequest:
    """
    Inserts a new compliance request.

    update_by is set the same value as created_by
    status defaults to ComplianceRequestStatus.SUBMITTED
    """

    compliance_request = ComplianceRequest(
        created_by=created_by,
        updated_by=created_by,
        status=ComplianceRequestStatus.SUBMITTED,
        classes={ComplianceRequestClass(compliance_class=c) for c in classes},
        runs={ComplianceRequestRun(compliance_run_id=r) for r in runs},
        csip_aus_version=csip_aus_version,
        witnessed_at=witnessed_at,
        der_brand=der_brand,
        der_oem=der_oem,
        der_series=der_series,
        der_representative_models=der_representative_models,
        software_client_type=software_client_type,
        software_client_providers=software_client_providers,
        software_client_versions=software_client_versions,
        onsite_hardware_details=onsite_hardware_details,
    )

    session.add(compliance_request)
    await session.flush()

    return compliance_request


async def update_compliance_request(
    session: AsyncSession,
    updated_by: int,
    compliance_request: ComplianceRequest,
    **kwargs: int | str | datetime | set[int] | set[str],
) -> None:
    """Updates the compliance request data"""
    for key, value in kwargs.items():
        if hasattr(compliance_request, key):
            # Classes and runs are stored in their own table so we need to
            # turn the serialized form (str for class, int for run) into the corresponding ORM model
            if key == "classes" and isinstance(value, set):
                value = {ComplianceRequestClass(compliance_class=c) for c in value}
            if key == "runs" and isinstance(value, set):
                value = {ComplianceRequestRun(compliance_run_id=r) for r in value}

            setattr(compliance_request, key, value)

    # update table metadata
    compliance_request.updated_at = datetime.now(UTC)
    compliance_request.updated_by = updated_by

    await session.flush()


async def safe_delete_compliance_request(session: AsyncSession, compliance_request: ComplianceRequest) -> bool:
    """Delete compliance request safely.

    Only allow deletion of compliance requests that haven't been finalised (at least once)

    Return:
        bool: Whether the compliance request could be deleted
    """
    if compliance_request.status in [ComplianceRequestStatus.FINALISED, ComplianceRequestStatus.REOPENED]:
        return False

    await delete_compliance_request(session=session, compliance_request=compliance_request)

    return True


async def delete_compliance_request(session: AsyncSession, compliance_request: ComplianceRequest) -> None:
    await session.delete(compliance_request)


async def select_user_compliance_request_finalisation(
    session: AsyncSession, user_id: int, compliance_request_id: int
) -> ComplianceRequestFinalisation | None:
    """
    Returns:


    Raises:
        NoResultFound exception if compliance_request_id not associated with user_id
        NoResultFound exception if no finalisation record associated with compliance_request_id
    """
    await select_user_compliance_request(session=session, user_id=user_id, compliance_request_id=compliance_request_id)

    stmt = (
        select(ComplianceRequestFinalisation)
        .where(ComplianceRequestFinalisation.compliance_request_id == compliance_request_id)
        .order_by(ComplianceRequestFinalisation.created_at.desc())
        .limit(1)
    )

    resp = await session.execute(stmt)
    return resp.scalar_one_or_none()


async def select_compliance_request_finalisation(
    session: AsyncSession, compliance_request_id: int
) -> ComplianceRequestFinalisation | None:
    stmt = (
        select(ComplianceRequestFinalisation)
        .where(ComplianceRequestFinalisation.compliance_request_id == compliance_request_id)
        .order_by(ComplianceRequestFinalisation.created_at.desc())
        .limit(1)
    )

    resp = await session.execute(stmt)
    return resp.scalar_one_or_none()


async def insert_compliance_request_finalisation(
    session: AsyncSession, compliance_request_id: int, created_at: datetime, created_by: int, file_data: bytes
) -> ComplianceRequestFinalisation:
    compliance_request_finalisation = ComplianceRequestFinalisation(
        compliance_request_id=compliance_request_id,
        created_at=created_at,
        created_by=created_by,
        file_data=file_data,
    )

    session.add(compliance_request_finalisation)
    await session.flush()

    return compliance_request_finalisation


async def insert_playlist_runs(
    session: AsyncSession,
    run_group_id: int,
    playlist_execution_id: str,
    test_procedure_ids: list[str],
    is_device_cert: bool,
    start_index: int = 0,
) -> list[Run]:
    """Create all Run records for a playlist execution.

    The run at start_index is set to 'provisioning' status (the first active run).
    Runs before start_index are marked as 'skipped' with finalised_at set.
    Runs after start_index are set to 'initialised'.
    All runs share the same teststack_id and playlist_execution_id.

    Args:
        start_index: The index to start execution from. Runs before this index
                     will be marked as skipped.
    """
    runs = []
    now = datetime.now(UTC)
    for order, procedure_id in enumerate(test_procedure_ids):
        if order < start_index:
            # Runs before start_index are skipped
            run = Run(
                run_group_id=run_group_id,
                pod_name=None,
                testprocedure_id=procedure_id,
                run_status=RunStatus.skipped,
                is_device_cert=is_device_cert,
                playlist_execution_id=playlist_execution_id,
                playlist_order=order,
                finalised_at=now,
            )
        elif order == start_index:
            # The run at start_index is the first active run
            run = Run(
                run_group_id=run_group_id,
                pod_name=None,
                testprocedure_id=procedure_id,
                run_status=RunStatus.provisioning,
                is_device_cert=is_device_cert,
                playlist_execution_id=playlist_execution_id,
                playlist_order=order,
            )
        else:
            # Runs after start_index are pending
            run = Run(
                run_group_id=run_group_id,
                pod_name=None,
                testprocedure_id=procedure_id,
                run_status=RunStatus.initialised,
                is_device_cert=is_device_cert,
                playlist_execution_id=playlist_execution_id,
                playlist_order=order,
            )
        session.add(run)
        runs.append(run)
    await session.flush()
    return runs


async def select_playlist_runs(
    session: AsyncSession,
    playlist_execution_id: str,
) -> Sequence[Run]:
    """Get all runs in a playlist, ordered by playlist_order."""
    stmt = select(Run).where(Run.playlist_execution_id == playlist_execution_id).order_by(Run.playlist_order)
    result = await session.execute(stmt)
    return result.scalars().all()


async def select_playlist_position_label(session: AsyncSession, run: Run) -> str | None:
    """Returns a "Test N of M" label for a playlist run (None if run isn't part of a playlist)."""
    if run.playlist_execution_id is None or run.playlist_order is None:
        return None
    count = await count_playlist_runs(session, run.playlist_execution_id)
    return f"Test {run.playlist_order + 1} of {count}"


async def count_playlist_runs(
    session: AsyncSession,
    playlist_execution_id: str,
) -> int:
    """Count the total number of runs in a playlist."""
    stmt = select(func.count()).select_from(Run).where(Run.playlist_execution_id == playlist_execution_id)
    result = await session.execute(stmt)
    return result.scalar_one()


async def select_next_playlist_run(
    session: AsyncSession,
    playlist_execution_id: str,
    current_order: int,
    for_update: bool = False,
) -> Run | None:
    """Get the run with the lowest playlist_order greater than current_order (tolerates gaps)."""
    stmt = (
        select(Run)
        .where(Run.playlist_execution_id == playlist_execution_id)
        .where(Run.playlist_order > current_order)
        .order_by(Run.playlist_order)
        .limit(1)
    )
    if for_update:
        stmt = stmt.with_for_update()
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def select_playlist_runs_for_update(
    session: AsyncSession,
    playlist_execution_id: str,
) -> Sequence[Run]:
    """Get all runs in a playlist, ordered by playlist_order, locking the rows for update."""
    stmt = (
        select(Run)
        .where(Run.playlist_execution_id == playlist_execution_id)
        .order_by(Run.playlist_order)
        .with_for_update()
    )
    result = await session.execute(stmt)
    return result.scalars().all()


async def delete_upcoming_playlist_runs(session: AsyncSession, playlist_execution_id: str, active_order: int) -> None:
    """Delete the not-yet-run tail of a playlist (playlist_order > active_order). The active run (which may
    itself still be 'initialised' if not yet started) and completed runs are untouched."""
    stmt = delete(Run).where(Run.playlist_execution_id == playlist_execution_id, Run.playlist_order > active_order)
    await session.execute(stmt)


async def insert_playlist_tail_runs(
    session: AsyncSession,
    run_group_id: int,
    playlist_execution_id: str,
    test_procedure_ids: list[str],
    is_device_cert: bool,
    pod_name: str | None,
    start_order: int,
) -> list[Run]:
    """Insert fresh 'initialised' Run rows for the upcoming tail of a playlist, starting at start_order.

    Callers are expected to have already deleted the old upcoming rows (delete_upcoming_playlist_runs) - this
    just inserts the replacements, contiguously numbered from start_order.
    """
    runs = []
    for offset, procedure_id in enumerate(test_procedure_ids):
        run = Run(
            run_group_id=run_group_id,
            pod_name=pod_name,
            testprocedure_id=procedure_id,
            run_status=RunStatus.initialised,
            is_device_cert=is_device_cert,
            playlist_execution_id=playlist_execution_id,
            playlist_order=start_order + offset,
        )
        session.add(run)
        runs.append(run)
    await session.flush()
    return runs


async def select_playlist_runs_with_status(
    session: AsyncSession,
    playlist_execution_id: str,
) -> Sequence[Run]:
    """
    Retrieve all runs in a playlist ordered by playlist_order.

    Returns: Sequence of Run objects
    """
    stmt = select(Run).where(Run.playlist_execution_id == playlist_execution_id).order_by(Run.playlist_order)
    result = await session.execute(stmt)
    return result.scalars().all()


async def select_admin_stats(
    session: AsyncSession,
    test_procedures_by_id: dict[TestProcedureId, Any],
) -> AdminStatsResponse:
    """
    Aggregates platform-wide stats for the admin stats page.

    total_passed/total_failed are based on the latest run per procedure per run group
    (i.e. the current pass/fail state, not historical retry counts).

    I nearly combined some of these queries to reduce the total number (some hit the same table twice), but I dont think
    the small performance benefit is worth the complexity of the queries needed.
    """

    # 1. Scalar totals from run table
    run_totals = await session.execute(select(func.count(Run.run_id), func.coalesce(func.max(Run.run_id), 0)))
    total_runs, max_run_id = run_totals.one()

    # 2. User count
    user_count_result = await session.execute(select(func.count(User.user_id)))
    total_users = user_count_result.scalar_one()

    # 3. Version counts (from run_group) — also derive total_run_groups
    version_result = await session.execute(
        select(RunGroup.csip_aus_version, func.count()).group_by(RunGroup.csip_aus_version)
    )
    version_counts: dict[str, int] = {}
    total_run_groups = 0
    for version, count in version_result.tuples().all():
        version_counts[version] = count
        total_run_groups += count

    # 4. Runs per ISO week
    iso_week = func.to_char(Run.created_at, 'IYYY-"W"IW').label("iso_week")
    week_result = await session.execute(select(iso_week, func.count()).group_by(iso_week))
    runs_per_week = dict(week_result.tuples().all())

    # 5. Runs per user (join through run_group)
    user_run_result = await session.execute(
        select(
            func.coalesce(User.user_name, cast(User.user_id, String)),
            func.count(Run.run_id),
        )
        .select_from(Run)
        .join(RunGroup, Run.run_group_id == RunGroup.run_group_id)
        .join(User, RunGroup.user_id == User.user_id)
        .group_by(User.user_id, User.user_name)
    )
    runs_per_user = dict(user_run_result.tuples().all())

    # 6. Per-procedure historical totals (pass/fail across all runs)
    proc_result = await session.execute(
        select(
            Run.testprocedure_id,
            func.count(),
            func.count(case((Run.all_criteria_met == True, 1))),  # noqa: E712
            func.count(case((Run.all_criteria_met == False, 1))),  # noqa: E712
        ).group_by(Run.testprocedure_id)
    )
    proc_totals = {row[0]: (row[1], row[2], row[3]) for row in proc_result.all()}

    # 7. Latest run per (run_group, procedure) — current pass/fail state
    #    Uses run_group_id_testprocedure_id_run_id_idx for the DISTINCT ON
    #    Grouped by procedure; top-level total_passed/total_failed derived in Python
    latest_by_proc = (
        select(Run.testprocedure_id, Run.all_criteria_met)
        .distinct(Run.run_group_id, Run.testprocedure_id)
        .order_by(Run.run_group_id, Run.testprocedure_id, Run.run_id.desc())
    ).subquery()
    latest_proc_result = await session.execute(
        select(
            latest_by_proc.c.testprocedure_id,
            func.count(case((latest_by_proc.c.all_criteria_met == True, 1))),  # noqa: E712
            func.count(case((latest_by_proc.c.all_criteria_met == False, 1))),  # noqa: E712
        )
        .select_from(latest_by_proc)
        .group_by(latest_by_proc.c.testprocedure_id)
    )
    proc_latest: dict[str, tuple[int, int]] = {}
    total_passed = 0
    total_failed = 0
    for row in latest_proc_result.all():
        proc_latest[row[0]] = (row[1], row[2])
        total_passed += row[1]
        total_failed += row[2]

    # Build procedure list from test definitions, merging in DB stats
    procedures = []
    for tp_id, definition in test_procedures_by_id.items():
        run_count, passed, failed = proc_totals.get(tp_id.value, (0, 0, 0))
        latest_passed, latest_failed = proc_latest.get(tp_id.value, (0, 0))
        procedures.append(
            {
                "test_procedure_id": tp_id.value,
                "classes": definition.classes,
                "total_runs": run_count,
                "passed": passed,
                "failed": failed,
                "latest_passed": latest_passed,
                "latest_failed": latest_failed,
            }
        )

    return AdminStatsResponse(
        total_runs=total_runs,
        max_run_id=max_run_id,
        total_passed=total_passed,
        total_failed=total_failed,
        total_users=total_users,
        total_run_groups=total_run_groups,
        version_counts=version_counts,
        runs_per_week=runs_per_week,
        runs_per_user=runs_per_user,
        procedures=procedures,
    )
