"""Moves certificate details off run_group and into a dedicated (user owned) certificate table.

Every run_group with a certificate is migrated to a certificate record. Run groups that were sharing the exact same
certificate (eg - via the legacy "shared aggregator certificate" endpoint) are migrated to a single, shared
certificate record. Run groups without a certificate (or with a NULL is_device_cert, which was previously treated as
"no certificate") are left unassigned.

Runs also reference the certificate they were created with (run.certificate_id). Only active runs are backfilled (from
their run group) - historical runs are left NULL as there is no way to know which certificate they actually used.

Revision ID: 7d3f1c9a4e21
Revises: 519cd6af59ae
Create Date: 2026-11-26 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7d3f1c9a4e21"
down_revision: str | None = "519cd6af59ae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "certificate",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("is_device_cert", sa.BOOLEAN(), nullable=False),
        sa.Column("certificate_pem", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generation", sa.Integer(), server_default="0", nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user_.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "user_id", name="certificate_id_user_id_key"),
    )
    op.create_index("certificate_user_id_idx", "certificate", ["user_id", "id"], unique=False)

    # One certificate per distinct (user, type, PEM) - identical PEM bytes means the groups were sharing a certificate
    op.execute(
        """
        INSERT INTO certificate (user_id, name, is_device_cert, certificate_pem, created_at, generated_at, generation)
        SELECT
            user_id,
            CASE WHEN COUNT(*) = 1 THEN MIN(name) ELSE 'Shared certificate' END,
            is_device_cert,
            certificate_pem,
            MIN(COALESCE(certificate_generated_at, created_at)),
            MAX(COALESCE(certificate_generated_at, created_at)),
            MAX(certificate_id)
        FROM run_group
        WHERE certificate_pem IS NOT NULL AND is_device_cert IS NOT NULL
        GROUP BY user_id, is_device_cert, certificate_pem
        ORDER BY MIN(id)
        """
    )

    # The old certificate_id (a per group generation counter) has been moved to certificate.generation. Drop it
    # before re-adding certificate_id as the reference to the certificate table
    op.drop_column("run_group", "certificate_id")
    op.add_column("run_group", sa.Column("certificate_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE run_group rg
        SET certificate_id = c.id
        FROM certificate c
        WHERE c.user_id = rg.user_id
            AND c.is_device_cert = rg.is_device_cert
            AND c.certificate_pem = rg.certificate_pem
        """
    )

    op.drop_column("run_group", "certificate_pem")
    op.drop_column("run_group", "is_device_cert")
    op.drop_column("run_group", "certificate_generated_at")

    op.create_index("run_group_certificate_id_idx", "run_group", ["certificate_id"], unique=False)
    op.create_foreign_key(
        "run_group_certificate_id_user_id_fkey",
        "run_group",
        "certificate",
        ["certificate_id", "user_id"],
        ["id", "user_id"],
    )

    op.add_column("run", sa.Column("certificate_id", sa.Integer(), nullable=True))
    op.create_index("run_certificate_id_idx", "run", ["certificate_id"], unique=False)
    op.create_foreign_key(
        "run_certificate_id_fkey", "run", "certificate", ["certificate_id"], ["id"], ondelete="SET NULL"
    )
    # Active runs = RunStatus initialised (1), started (2), provisioning (6)
    op.execute(
        """
        UPDATE run r
        SET certificate_id = c.id
        FROM run_group rg
        JOIN certificate c ON c.id = rg.certificate_id
        WHERE r.run_group_id = rg.id
            AND r.run_status IN (1, 2, 6)
            AND r.is_device_cert = c.is_device_cert
        """
    )


def downgrade() -> None:
    op.drop_constraint("run_certificate_id_fkey", "run", type_="foreignkey")
    op.drop_index("run_certificate_id_idx", table_name="run")
    op.drop_column("run", "certificate_id")

    op.drop_constraint("run_group_certificate_id_user_id_fkey", "run_group", type_="foreignkey")
    op.drop_index("run_group_certificate_id_idx", table_name="run_group")

    op.add_column("run_group", sa.Column("is_device_cert", sa.BOOLEAN(), nullable=True))
    op.add_column("run_group", sa.Column("certificate_pem", sa.LargeBinary(), nullable=True))
    op.add_column("run_group", sa.Column("certificate_generated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("run_group", sa.Column("certificate_counter", sa.Integer(), nullable=False, server_default="0"))

    # Shared certificates are copied onto every run group they're assigned to
    op.execute(
        """
        UPDATE run_group rg
        SET is_device_cert = c.is_device_cert,
            certificate_pem = c.certificate_pem,
            certificate_generated_at = c.generated_at,
            certificate_counter = c.generation
        FROM certificate c
        WHERE c.id = rg.certificate_id
        """
    )

    op.drop_column("run_group", "certificate_id")
    op.alter_column("run_group", "certificate_counter", new_column_name="certificate_id")

    op.drop_index("certificate_user_id_idx", table_name="certificate")
    op.drop_table("certificate")
