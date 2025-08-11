from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from cactus_test_definitions.test_procedures import CSIPAusVersion, TestProcedureId
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload, undefer

from cactus_orchestrator.model import Run, RunArtifact, RunGroup, RunStatus, User
from cactus_orchestrator.schema import UserContext


async def insert_run_group(session: AsyncSession, user_id: int, csip_aus_version: str) -> RunGroup:
    """Inserts a new RunGroup with the specified csip_aus_version. Returns the inserted RunGroup."""

    new_group = RunGroup(name="New Group", csip_aus_version=csip_aus_version, user_id=user_id)
    session.add(new_group)
    await session.flush()
    return new_group


async def insert_user(session: AsyncSession, user_context: UserContext) -> User:
    """Inserts a new user with no certificate details and default config. Returns the new User ID. Raises exceptions
    if a user with the same user_context already exists in the database. Returns a User with all props being
    undeferred"""

    user = User(
        subject_id=user_context.subject_id,
        issuer_id=user_context.issuer_id,
        run_groups=[RunGroup(name="Default Group", csip_aus_version=CSIPAusVersion.RELEASE_1_2.value)],
    )
    session.add(user)
    await session.flush()

    new_user = await select_user(session, user_context, True, True, True, True)
    if new_user is None:
        raise Exception(f"Unable to insert new user for user_context {user_context}")

    return new_user


async def select_user(
    session: AsyncSession,
    user_context: UserContext,
    with_aggregator_der: bool = False,
    with_aggregator_p12: bool = False,
    with_device_der: bool = False,
    with_device_p12: bool = False,
) -> User | None:

    stmt = select(User).where(
        and_(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
    )

    options_list = []
    if with_aggregator_p12:
        options_list.append(undefer(User.aggregator_certificate_p12_bundle))
    if with_aggregator_der:
        options_list.append(undefer(User.aggregator_certificate_x509_der))
    if with_device_p12:
        options_list.append(undefer(User.device_certificate_p12_bundle))
    if with_device_der:
        options_list.append(undefer(User.device_certificate_x509_der))

    if options_list:
        stmt = stmt.options(*options_list)

    res = await session.execute(stmt)
    return res.scalar_one_or_none()


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


async def select_run_groups_for_user(session: AsyncSession, user_id: int) -> Sequence[RunGroup]:
    resp = await session.execute(select(RunGroup).where(RunGroup.user_id == user_id).order_by(RunGroup.run_group_id))
    return resp.scalars().all()


async def select_run_group_for_user(session: AsyncSession, user_id: int, run_group_id: int) -> RunGroup | None:
    resp = await session.execute(
        select(RunGroup).where(((RunGroup.user_id == user_id) & (RunGroup.run_group_id == run_group_id))).limit(1)
    )
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
        filters.append(
            Run.run_status.in_(
                (RunStatus.finalised_by_client.value, RunStatus.finalised_by_timeout.value, RunStatus.terminated.value)
            )
        )
    elif finalised is False:
        filters.append(
            Run.run_status.in_((RunStatus.initialised.value, RunStatus.started.value, RunStatus.provisioning.value))
        )

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
        .where(Run.run_status.in_((RunStatus.initialised.value, RunStatus.started.value)))
        .options(selectinload(Run.run_group))
        .order_by(Run.run_id.desc())
    )

    resp = await session.execute(stmt)
    return resp.scalars().all()


async def select_nonfinalised_runs(session: AsyncSession) -> Sequence[Run]:
    stmt = select(Run).where(Run.run_status.in_((RunStatus.started.value, RunStatus.initialised.value)))
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
    raw_counts = dict((r.tuple() for r in count_resp.all()))

    # Do the "distinct on" query for the latest runs by type
    stmt = (
        select(Run.testprocedure_id, Run.all_criteria_met)
        .distinct(Run.testprocedure_id)
        .order_by(Run.testprocedure_id, Run.run_id.desc())
        .where(Run.run_group_id == run_group_id)
    )
    distinct_resp = await session.execute(stmt)
    raw_criteria = dict((r.tuple() for r in distinct_resp.all()))

    return [
        ProcedureRunAggregated(
            test_procedure_id=tp,
            count=raw_counts.get(tp.value, 0),
            latest_all_criteria_met=raw_criteria.get(tp.value, None),
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
