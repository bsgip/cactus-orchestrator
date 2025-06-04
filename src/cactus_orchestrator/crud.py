from datetime import datetime

from sqlalchemy import and_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, undefer

from cactus_orchestrator.model import RunStatus, Run, RunArtifact, User, UserUniqueConstraintName
from cactus_orchestrator.schema import UserContext


async def insert_user(
    session: AsyncSession, user_context: UserContext, client_p12: bytes, client_x509_der: bytes
) -> User:

    user = User(
        subject_id=user_context.subject_id,
        issuer_id=user_context.issuer_id,
        certificate_p12_bundle=client_p12,
        certificate_x509_der=client_x509_der,
    )

    session.add(user)
    await session.flush()
    return user


async def update_user(
    session: AsyncSession, user_context: UserContext, client_p12: bytes, client_x509_der: bytes
) -> int | None:
    """Update an existing user's certificate. Returns user_id if successful, None if user does not exist."""

    stmt = (
        update(User)
        .where((User.subject_id == user_context.subject_id) & (User.issuer_id == user_context.issuer_id))
        .values(
            certificate_x509_der=client_x509_der,
            certificate_p12_bundle=client_p12,
        )
        .returning(User.user_id)
    )

    resp = await session.execute(stmt)
    user_id = resp.scalar_one_or_none()

    if user_id:
        await session.commit()

    return user_id


async def upsert_user(
    session: AsyncSession, user_context: UserContext, client_p12: bytes, client_x509_der: bytes
) -> int:
    """We have to use sqlalchemy-core with postgres dialect for upserts"""
    # form statement
    stmt = insert(User).values(
        subject_id=user_context.subject_id,
        issuer_id=user_context.issuer_id,
        certificate_x509_der=client_x509_der,
        certificate_p12_bundle=client_p12,
    )

    resp = await session.execute(
        stmt.on_conflict_do_update(
            constraint=UserUniqueConstraintName,
            set_=dict(
                certificate_x509_der=client_x509_der,
                certificate_p12_bundle=client_p12,
            ),
        ).returning(User.user_id)
    )
    return resp.scalar_one()


async def select_user(
    session: AsyncSession, user_context: UserContext, with_der: bool = False, with_p12: bool = False
) -> User | None:

    stmt = select(User).where(
        and_(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
    )

    options_list = []
    if with_p12:
        options_list.append(undefer(User.certificate_p12_bundle))
    if with_der:
        options_list.append(undefer(User.certificate_x509_der))

    if options_list:
        stmt = stmt.options(*options_list)

    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def select_user_certificate_x509_der(session: AsyncSession, user_context: UserContext) -> bytes | None:
    stmt = select(User.certificate_x509_der).where(
        and_(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one()


async def insert_run_for_user(
    session: AsyncSession, user_id: int, teststack_id: str, testprocedure_id: str, run_status: RunStatus
) -> int:
    run = Run(
        user_id=user_id,
        teststack_id=teststack_id,
        testprocedure_id=testprocedure_id,
        run_status=run_status,
    )
    session.add(run)
    await session.flush()
    return run.run_id


async def select_user_runs(
    session: AsyncSession, user_id: int, finalised: bool | None, created_at_gte: datetime | None
) -> list[Run | None]:
    # runs statement
    stmt = select(Run).where(Run.user_id == user_id)
    filters = []
    if created_at_gte is not None:
        filters.append(Run.created_at >= created_at_gte)

    if finalised is True:
        filters.append(Run.run_status.in_((RunStatus.finalised_by_client.value, RunStatus.finalised_by_timeout.value)))
    elif finalised is False:
        filters.append(Run.run_status.in_((RunStatus.initialised.value, RunStatus.started.value)))

    if filters:
        stmt = stmt.where(and_(*filters))

    res = await session.execute(stmt)
    return list(res.scalars().all())


async def select_nonfinalised_runs(session: AsyncSession) -> list[Run]:
    stmt = select(Run).where(Run.run_status.in_((RunStatus.started.value, RunStatus.initialised.value)))
    res = await session.execute(stmt)
    return list(res.scalars().all())


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
    run_artifact_id: int,
    run_status: RunStatus,
    finalised_at: datetime,
) -> None:
    run.run_artifact_id = run_artifact_id
    run.finalised_at = finalised_at
    run.run_status = run_status
    await session.flush()


async def select_user_run(session: AsyncSession, user_id: int, run_id: int) -> Run:
    stmt = select(Run).where(
        and_(
            Run.run_id == run_id,
            Run.user_id == user_id,
        )
    )

    resp = await session.execute(stmt)

    return resp.scalar_one()


async def select_user_run_with_artifact(session: AsyncSession, user_id: int, run_id: int) -> Run:
    stmt = (
        select(Run)
        .where(
            and_(
                Run.run_id == run_id,
                Run.user_id == user_id,
            )
        )
        .options(joinedload(Run.run_artifact))
    )

    resp = await session.execute(stmt)

    return resp.scalar_one()
