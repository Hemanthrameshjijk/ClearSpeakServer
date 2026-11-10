"""organisations get seats/validity/features, admins get roles, payments table

Revision ID: a1b2c3d4e5f6
Revises: f29a1db16e0f
"""
import json
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "f29a1db16e0f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("orgs") as b:
        b.add_column(sa.Column("status", sa.String(20), nullable=False, server_default="active"))
        b.add_column(sa.Column("seats", sa.Integer, nullable=False, server_default="0"))
        b.add_column(sa.Column("paid_until", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("features", sa.JSON, nullable=False, server_default="[]"))
        b.add_column(sa.Column("seat_price_paise", sa.Integer, nullable=True))
    with op.batch_alter_table("admin_users") as b:
        b.add_column(sa.Column("name", sa.String(200), nullable=False, server_default=""))
        b.add_column(sa.Column("role", sa.String(10), nullable=False, server_default="admin"))
        b.add_column(sa.Column("must_change_password", sa.Boolean, nullable=False, server_default=sa.false()))
        b.add_column(sa.Column("totp_enabled", sa.Boolean, nullable=False, server_default=sa.true()))
    with op.batch_alter_table("audit_log") as b:
        b.add_column(sa.Column("org_id", sa.String(36), nullable=True))
    op.create_table(
        "payments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("kind", sa.String(12), nullable=False),
        sa.Column("seats", sa.Integer, nullable=False),
        sa.Column("months", sa.Integer, nullable=False),
        sa.Column("amount_paise", sa.Integer, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("provider_order_id", sa.String(100), nullable=False, unique=True),
        sa.Column("provider_payment_id", sa.String(100), nullable=False, server_default=""),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("admin_users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Organisations that already exist keep working: give them 10 seats, a year, and every feature.
    conn = op.get_bind()
    until = datetime.now(timezone.utc) + timedelta(days=365)
    conn.execute(sa.text("UPDATE orgs SET seats = 10, paid_until = :u, features = :f"), {"u": until, "f": json.dumps(["accent", "bvc", "nc"])})
    conn.execute(sa.text("UPDATE admin_users SET role = 'owner' WHERE org_id IS NOT NULL"))


def downgrade() -> None:
    op.drop_table("payments")
    with op.batch_alter_table("audit_log") as b:
        b.drop_column("org_id")
    with op.batch_alter_table("admin_users") as b:
        for c in ("totp_enabled", "must_change_password", "role", "name"):
            b.drop_column(c)
    with op.batch_alter_table("orgs") as b:
        for c in ("seat_price_paise", "features", "paid_until", "seats", "status"):
            b.drop_column(c)
