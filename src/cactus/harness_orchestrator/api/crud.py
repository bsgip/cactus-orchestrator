from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import deferred

from cactus.harness_orchestrator.model import User, UserUniqueConstraintName
from cactus.harness_orchestrator.schema import UserContext


async def create_or_update_user(
    session: AsyncSession, user_context: UserContext, client_p12: bytes, client_x509_der: bytes
) -> User:
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
    )

    resp = await session.execute(stmt)
    return resp.scalar_one()


async def get_user(session: AsyncSession, user_context: UserContext) -> User:
    return (
        await session.query(User)
        .filter(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
        .first()
    )


async def get_user_certificate_x509_der(session: AsyncSession, user_context: UserContext) -> bytes:
    return (
        await session.query(User.certificate_x509_der)
        .filter(User.subject_id == user_context.subject_id, User.issuer_id == user_context.issuer_id)
        .first()
    )[0]
