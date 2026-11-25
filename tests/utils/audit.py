from collections.abc import Sequence

from assertical.asserts.time import assert_nowish
from assertical.fixtures.postgres import generate_async_session
from sqlalchemy import select

from cactus_orchestrator.model import AuditChangeType, AuditLog


async def assert_audit_logs(pg_config, expected: Sequence[tuple[int, AuditChangeType, list[int]]]) -> None:
    """Asserts that the DB contains exactly the expected (user_id, change_type, record_ids) audit logs (in order).
    The order of record_ids isn't considered"""
    async with generate_async_session(pg_config) as session:
        logs = (await session.execute(select(AuditLog).order_by(AuditLog.audit_log_id))).scalars().all()

    actual = [(log.user_id, AuditChangeType(log.change_type), sorted(log.record_ids)) for log in logs]
    assert actual == [(user_id, change_type, sorted(ids)) for user_id, change_type, ids in expected]
    for log in logs:
        assert log.description
        assert_nowish(log.created_at)
