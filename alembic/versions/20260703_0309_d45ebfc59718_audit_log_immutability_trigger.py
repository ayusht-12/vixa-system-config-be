"""audit log immutability trigger

Revision ID: d45ebfc59718
Revises: 570702d1f582
Create Date: 2026-07-03 03:09:29.041145

Enforces append-only semantics on ``audit_log_entries`` at the database
level: any UPDATE or DELETE against the table raises an exception, so the
hash chain cannot be tampered with even by a client holding raw SQL access
(e.g. an ops engineer at a psql prompt), not just through the API.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd45ebfc59718'
down_revision: Union[str, None] = '570702d1f582'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_FUNCTION_NAME = "reject_audit_log_mutation"
_TRIGGER_NAME = "trg_audit_log_immutable"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {_FUNCTION_NAME}()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION
                'audit_log_entries is append-only: % is not permitted (sequence=%)',
                TG_OP,
                OLD.sequence;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER {_TRIGGER_NAME}
        BEFORE UPDATE OR DELETE ON audit_log_entries
        FOR EACH ROW EXECUTE FUNCTION {_FUNCTION_NAME}();
        """
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER IF EXISTS {_TRIGGER_NAME} ON audit_log_entries;")
    op.execute(f"DROP FUNCTION IF EXISTS {_FUNCTION_NAME}();")
