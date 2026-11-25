import logging
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, SessionTransaction

from cactus_orchestrator.model import AuditChangeType, AuditLog

logger = logging.getLogger(__name__)

PENDING_MESSAGES_KEY = "audit_log_pending_messages"


def audit_log(
    session: AsyncSession,
    user_id: int,
    change_type: AuditChangeType,
    record_ids: int | Iterable[int],
    description: str,
) -> None:
    """Records a write operation to the audit_log DB table AND to the application logs. Call this before committing.

    The audit record joins the current transaction, so it's persisted if (and only if) the change it describes is. The
    application log is held until the outcome of that transaction is known: INFO on commit or WARNING on rollback.

    session: The session making the change
    user_id: The user that triggered the change (eg the admin, not the owner of the records). Use
             AUDIT_SYSTEM_USER_ID for changes made by automated processes (eg background tasks)
    change_type: The rough category of change - also identifies what sort of record that record_ids references
    record_ids: The ID(s) of the affected record(s). Newly inserted records will need to be flushed to have an ID
    description: Human readable description of the change. Use !r when including user supplied text
    """
    record_ids = [record_ids] if isinstance(record_ids, int) else list(record_ids)

    session.add(
        AuditLog(
            # now() in postgres is the transaction start time - which can be much earlier (eg if spawning a pod)
            created_at=datetime.now(UTC),
            user_id=user_id,
            change_type=change_type,
            record_ids=record_ids,
            description=description,
        )
    )
    session.info.setdefault(PENDING_MESSAGES_KEY, []).append(
        f"{change_type.name} user={user_id} records={record_ids}: {description}"
    )


@event.listens_for(Session, "after_commit")
def _log_committed(session: Session) -> None:
    if session.in_nested_transaction():
        return  # Releasing a savepoint - nothing has been persisted yet

    for message in session.info.pop(PENDING_MESSAGES_KEY, []):
        logger.info(f"Audit: {message}")


@event.listens_for(Session, "after_transaction_end")
def _log_rolled_back(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is not None:
        return

    # Runs after _log_committed. Anything left was rolled back (either explicitly or via the session being closed)
    for message in session.info.pop(PENDING_MESSAGES_KEY, []):
        logger.warning(f"Audit: ROLLED BACK {message}")
