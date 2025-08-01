"""add_criteria_met

Revision ID: 4e0791b908bd
Revises: 49a5dd29ff0b
Create Date: 2025-07-14 22:29:29.267871

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4e0791b908bd"
down_revision: Union[str, None] = "49a5dd29ff0b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("run", sa.Column("all_criteria_met", sa.BOOLEAN(), nullable=True))
    op.create_index(
        "user_id_testprocedure_id_run_id_idx",
        "run",
        ["user_id", "testprocedure_id", sa.literal_column("id DESC")],
        unique=False,
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index("user_id_testprocedure_id_run_id_idx", table_name="run")
    op.drop_column("run", "all_criteria_met")
    # ### end Alembic commands ###
