"""audit log sequence as identity column

Revision ID: 89569d590a49
Revises: d8148ec2aa08
Create Date: 2026-07-03 11:49:28.235117

`sequence` is a secondary (non-PK) column, so SQLAlchemy's
`autoincrement=True` never actually applied at the DDL level — Postgres
was leaving it NULL on every insert. Converting it to a proper
GENERATED ALWAYS AS IDENTITY column lets Postgres assign it atomically.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '89569d590a49'
down_revision: Union[str, None] = 'd8148ec2aa08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE audit_log_entries "
        "ALTER COLUMN sequence ADD GENERATED ALWAYS AS IDENTITY"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE audit_log_entries "
        "ALTER COLUMN sequence DROP IDENTITY IF EXISTS"
    )
