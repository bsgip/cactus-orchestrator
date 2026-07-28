"""add_run_warnings

Revision ID: 3cfee29820b0
Revises: 4bc8586aa906
Create Date: 2026-07-28 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3cfee29820b0"
down_revision: str | None = "4bc8586aa906"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("run", sa.Column("warnings", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column("run", "warnings")
