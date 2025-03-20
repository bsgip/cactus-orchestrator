from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert

from cactus.harness_orchestrator.model import User, UserUniqueConstraintName
from cactus.harness_orchestrator.schema import UserContext


async def add_user(session: AsyncSession, user_context: UserContext, client_p12: bytes, client_x509_der: bytes) -> User:

    user = User(
        subject_id=user_context.subject_id,
        issuer_id=user_context.issuer_id,
        certificate_p12_bundle=client_p12,
        certificate_x509_der=client_x509_der,
    )

    session.add(user)
    await session.flush()
    return user


async def add_or_update_user(
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
    stmt = stmt.on_conflict_do_update(
        constraint=UserUniqueConstraintName,
        set_=dict(
            certificate_x509_der=client_x509_der,
            certificate_p12_bundle=client_p12,
        ),
    ).returning(User.user_id)

    resp = await session.execute(stmt)
    return resp.scalar_one_or_none()


async def get_user(session: AsyncSession, user_context: UserContext) -> User | None:

    stmt = select(User).where(
        and_(user_context.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def get_user_certificate_x509_der(session: AsyncSession, user_context: UserContext) -> bytes | None:
    stmt = select(User.certificate_x509_der).where(
        and_(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()
