from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from cactus_test_definitions import CSIPAusVersion
from cactus_test_definitions.client import TestProcedureId
from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload, undefer

from cactus_orchestrator.auth import UserContext
from cactus_orchestrator.model import ComplianceRecord, Run, RunArtifact, RunGroup, RunStatus, User

ACTIVE_RUN_STATUSES: set[RunStatus] = {RunStatus.provisioning, RunStatus.started, RunStatus.initialised}
FINALISED_RUN_STATUSES: set[RunStatus] = {
    RunStatus.finalised_by_client,
    RunStatus.finalised_by_timeout,
    RunStatus.terminated,
    RunStatus.skipped,
}


async def insert_run_group(session: AsyncSession, user_id: int, csip_aus_version: str) -> RunGroup:
    """Inserts a new RunGroup with the specified csip_aus_version. Returns the inserted RunGroup."""

    new_group = RunGroup(name="New Group", csip_aus_version=csip_aus_version, user_id=user_id)
    session.add(new_group)
    await session.flush()
    return new_group


async def insert_user(session: AsyncSession, user_context: UserContext) -> User:
    """Inserts a new user with no certificate details and default config. Returns the new User ID. Raises exceptions
    if a user with the same user_context already exists in the database."""

    user = User(
        subject_id=user_context.subject_id,
        issuer_id=user_context.issuer_id,
        run_groups=[RunGroup(name="Default Group", csip_aus_version=CSIPAusVersion.RELEASE_1_2.value)],
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
    teststack_id: str,
    testprocedure_id: str,
    run_status: RunStatus,
    is_device_cert: bool,
) -> int:
    run = Run(
        run_group_id=run_group_id,
        teststack_id=teststack_id,
        testprocedure_id=testprocedure_id,
        run_status=run_status,
        is_device_cert=is_device_cert,
    )
    session.add(run)
    await session.flush()
    return run.run_id


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


async def select_run_groups_for_user(session: AsyncSession, user_id: int) -> Sequence[RunGroup]:
    resp = await session.execute(select(RunGroup).where(RunGroup.user_id == user_id).order_by(RunGroup.run_group_id))
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
    session: AsyncSession, user_id: int, run_group_id: int, with_cert: bool = False
) -> RunGroup | None:
    stmt = select(RunGroup).where(((RunGroup.user_id == user_id) & (RunGroup.run_group_id == run_group_id))).limit(1)
    if with_cert:
        stmt = stmt.options(undefer(RunGroup.certificate_pem))

    resp = await session.execute(stmt)
    return resp.scalar_one_or_none()


async def delete_runs(session: AsyncSession, runs: Sequence[Run]) -> None:
    run_artifact_ids = [r.run_artifact_id for r in runs if r.run_artifact_id is not None]
    for run in runs:
        await session.delete(run)
    if run_artifact_ids:
        await session.execute(delete(RunArtifact).where(RunArtifact.run_artifact_id.in_(run_artifact_ids)))


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
        .options(selectinload(Run.run_group))
        .order_by(Run.run_id.desc())
    )

    resp = await session.execute(stmt)
    return resp.scalars().all()


async def select_nonfinalised_runs(session: AsyncSession) -> Sequence[Run]:
    stmt = select(Run).where(Run.run_status.in_(ACTIVE_RUN_STATUSES))
    resp = await session.execute(stmt)
    return resp.scalars().all()


async def update_run_run_status(
    session: AsyncSession, run_id: int, run_status: RunStatus, finalised_at: datetime | None = None
) -> None:
    stmt = update(Run).where(Run.run_id == run_id).values(run_status=run_status, finalised_at=finalised_at)
    await session.execute(stmt)


async def create_runartifact(session: AsyncSession, compression: str, file_data: bytes) -> RunArtifact:
    runartifact = RunArtifact(compression=compression, file_data=file_data)
    session.add(runartifact)
    await session.flush()
    return runartifact


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
    raw_counts = dict((r._tuple() for r in count_resp.all()))

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


async def insert_playlist_runs(
    session: AsyncSession,
    run_group_id: int,
    teststack_id: str,
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
    now = datetime.now(timezone.utc)
    for order, procedure_id in enumerate(test_procedure_ids):
        if order < start_index:
            # Runs before start_index are skipped
            run = Run(
                run_group_id=run_group_id,
                teststack_id=teststack_id,
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
                teststack_id=teststack_id,
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
                teststack_id=teststack_id,
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
) -> Run | None:
    """Get the next run in a playlist after the given order position."""
    stmt = (
        select(Run)
        .where(Run.playlist_execution_id == playlist_execution_id)
        .where(Run.playlist_order == current_order + 1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
