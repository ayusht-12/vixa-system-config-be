"""add compliance_score_snapshots

Revision ID: c3d5e7f9a1b2
Revises: b2c4d6e8f012
Create Date: 2026-07-03 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d5e7f9a1b2'
down_revision: Union[str, None] = 'b2c4d6e8f012'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'compliance_score_snapshots',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('framework_id', sa.UUID(), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_compliance_score_snapshots_framework_id'),
        'compliance_score_snapshots',
        ['framework_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_compliance_score_snapshots_captured_at'),
        'compliance_score_snapshots',
        ['captured_at'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_compliance_score_snapshots_captured_at'),
        table_name='compliance_score_snapshots',
    )
    op.drop_index(
        op.f('ix_compliance_score_snapshots_framework_id'),
        table_name='compliance_score_snapshots',
    )
    op.drop_table('compliance_score_snapshots')
