import logging

import pytest
from assertical.fixtures.postgres import generate_async_session
from sqlalchemy import select

from cactus_orchestrator.audit import audit_log
from cactus_orchestrator.model import AUDIT_SYSTEM_USER_ID, AuditChangeType, AuditLog, User
from tests.utils.audit import assert_audit_logs


@pytest.fixture
def audit_messages(caplog):
    """Fetches the (level, message) of everything logged by cactus_orchestrator.audit"""
    caplog.set_level(logging.INFO, logger="cactus_orchestrator.audit")
    return lambda: [(r.levelno, r.getMessage()) for r in caplog.records if r.name == "cactus_orchestrator.audit"]


def test_audit_log_no_foreign_keys():
    assert all(len(c.foreign_keys) == 0 for c in AuditLog.__table__.columns)


@pytest.mark.parametrize(
    "record_ids, expected_record_ids", [(5, [5]), ([5], [5]), ((3, 1), [3, 1]), ((i for i in [1, 2]), [1, 2]), ([], [])]
)
@pytest.mark.asyncio
async def test_audit_log_commit(pg_empty_config, audit_messages, record_ids, expected_record_ids):
    """The user/records in this test don't exist - it doesn't matter"""
    async with generate_async_session(pg_empty_config) as session:
        audit_log(session, 99, AuditChangeType.RUN_DELETED, record_ids, "My description 100%s")
        assert audit_messages() == [], "Nothing logged until committed"
        await session.commit()

        expected = [(logging.INFO, f"Audit: RUN_DELETED user=99 records={expected_record_ids}: My description 100%s")]
        assert audit_messages() == expected

        await session.commit()
    assert audit_messages() == expected, "Logged exactly once"

    await assert_audit_logs(pg_empty_config, [(99, AuditChangeType.RUN_DELETED, expected_record_ids)])
    async with generate_async_session(pg_empty_config) as session:
        assert (await session.execute(select(AuditLog))).scalar_one().description == "My description 100%s"


@pytest.mark.asyncio
async def test_audit_log_system_user(pg_empty_config):
    async with generate_async_session(pg_empty_config) as session:
        audit_log(session, AUDIT_SYSTEM_USER_ID, AuditChangeType.RUN_UPDATED, 1, "desc")
        await session.commit()
    await assert_audit_logs(pg_empty_config, [(-1, AuditChangeType.RUN_UPDATED, [1])])


@pytest.mark.parametrize("flush", [True, False])
@pytest.mark.parametrize("explicit_rollback", [True, False])
@pytest.mark.asyncio
async def test_audit_log_rollback(pg_empty_config, audit_messages, flush: bool, explicit_rollback: bool):
    """Rolling back (or just closing the session without a commit) is logged as such and persists nothing"""
    async with generate_async_session(pg_empty_config) as session:
        audit_log(session, 1, AuditChangeType.RUN_DELETED, 2, "desc")
        if flush:
            await session.flush()
        if explicit_rollback:
            await session.rollback()

    assert audit_messages() == [(logging.WARNING, "Audit: ROLLED BACK RUN_DELETED user=1 records=[2]: desc")]
    await assert_audit_logs(pg_empty_config, [])


@pytest.mark.asyncio
async def test_audit_log_commit_failure(pg_base_config, audit_messages):
    """If the commit itself fails - the audit log shouldn't be persisted. The session can then be reused"""
    async with generate_async_session(pg_base_config) as session:
        session.add(User(subject_id="user1", issuer_id="https://test-cactus-issuer.example.com"))  # Already exists
        audit_log(session, 1, AuditChangeType.USER_CREATED, 2, "first")
        with pytest.raises(Exception, match="subject_id_issuer_id_key"):
            await session.commit()
        await session.rollback()
        assert audit_messages() == [(logging.WARNING, "Audit: ROLLED BACK USER_CREATED user=1 records=[2]: first")]

        audit_log(session, 1, AuditChangeType.USER_UPDATED, 3, "second")
        await session.commit()

    assert audit_messages()[1:] == [(logging.INFO, "Audit: USER_UPDATED user=1 records=[3]: second")]
    await assert_audit_logs(pg_base_config, [(1, AuditChangeType.USER_UPDATED, [3])])


@pytest.mark.asyncio
async def test_audit_log_savepoint_release(pg_empty_config, audit_messages):
    """Releasing a savepoint isn't a commit"""
    async with generate_async_session(pg_empty_config) as session:
        async with session.begin_nested():
            audit_log(session, 1, AuditChangeType.RUN_DELETED, 2, "desc")
        assert audit_messages() == []
        await session.commit()
        assert audit_messages() == [(logging.INFO, "Audit: RUN_DELETED user=1 records=[2]: desc")]
