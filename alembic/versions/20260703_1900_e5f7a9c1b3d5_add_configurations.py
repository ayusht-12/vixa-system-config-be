"""add configurations (versioned config documents)

Revision ID: e5f7a9c1b3d5
Revises: d4e6f8a0b1c3
Create Date: 2026-07-03 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f7a9c1b3d5'
down_revision: Union[str, None] = 'd4e6f8a0b1c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'configurations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column(
            'status',
            sa.Enum('DRAFT', 'ACTIVE', 'ARCHIVED', name='configurationstatus', native_enum=False),
            nullable=False,
        ),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('sensitive_keys', sa.JSON(), nullable=False),
        sa.Column('checksum', sa.String(length=64), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('created_by', sa.String(length=120), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', 'version', name='uq_configurations_name_version'),
    )
    op.create_index(op.f('ix_configurations_name'), 'configurations', ['name'], unique=False)
    op.create_index(op.f('ix_configurations_status'), 'configurations', ['status'], unique=False)
    op.create_index(
        op.f('ix_configurations_deleted_at'), 'configurations', ['deleted_at'], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_configurations_deleted_at'), table_name='configurations')
    op.drop_index(op.f('ix_configurations_status'), table_name='configurations')
    op.drop_index(op.f('ix_configurations_name'), table_name='configurations')
    op.drop_table('configurations')
