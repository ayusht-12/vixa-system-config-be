"""add compliance_assessments

Revision ID: b2c4d6e8f012
Revises: a7f3c9b2e1d4
Create Date: 2026-07-03 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c4d6e8f012'
down_revision: Union[str, None] = 'a7f3c9b2e1d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'compliance_assessments',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('framework_id', sa.UUID(), nullable=False),
        sa.Column(
            'status',
            sa.Enum('IN_PROGRESS', 'COMPLETED', name='assessmentstatus', native_enum=False),
            nullable=False,
        ),
        sa.Column('started_by', sa.String(length=255), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('score', sa.Float(), nullable=True),
        sa.Column('total_controls', sa.Integer(), nullable=True),
        sa.Column('mapped_controls', sa.Integer(), nullable=True),
        sa.Column('gap_controls', sa.Integer(), nullable=True),
        sa.Column('notes', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_compliance_assessments_framework_id'),
        'compliance_assessments',
        ['framework_id'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_compliance_assessments_framework_id'),
        table_name='compliance_assessments',
    )
    op.drop_table('compliance_assessments')
