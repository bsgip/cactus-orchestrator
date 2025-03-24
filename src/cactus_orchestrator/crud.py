from sqlalchemy import and_, select, update
from sqlalchemy.orm import undefer
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.model import User, UserUniqueConstraintName, Run
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
) -> int | None:
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
    return resp.scalar_one_or_none()


async def select_user(session: AsyncSession, user_context: UserContext) -> User | None:

    stmt = (
        select(User)
        .where(and_(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id))
        .options(undefer(User.certificate_p12_bundle))
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def select_user_certificate_x509_der(session: AsyncSession, user_context: UserContext) -> bytes | None:
    stmt = select(User.certificate_x509_der).where(
        and_(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def insert_run_for_user(session: AsyncSession, user_id: int, teststack_id: str, testprocedure_id: str) -> int:
    run = Run(user_id=user_id, teststack_id=teststack_id, testprocedure_id=testprocedure_id)
    session.add(run)
    await session.flush()
    return run.run_id
