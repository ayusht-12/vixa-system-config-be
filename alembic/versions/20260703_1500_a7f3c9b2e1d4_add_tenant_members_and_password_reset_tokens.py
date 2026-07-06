"""add tenant_members and password_reset_tokens

Revision ID: a7f3c9b2e1d4
Revises: 4bb68c116149
Create Date: 2026-07-03 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7f3c9b2e1d4'
down_revision: Union[str, None] = '4bb68c116149'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_password_reset_tokens_user_id'),
        'password_reset_tokens',
        ['user_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_password_reset_tokens_token_hash'),
        'password_reset_tokens',
        ['token_hash'],
        unique=True,
    )

    op.create_table(
        'tenant_members',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column(
            'role',
            sa.Enum('OWNER', 'ADMIN', 'ANALYST', 'VIEWER', name='tenantmemberrole', native_enum=False),
            nullable=False,
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'user_id', name='uq_tenant_members_tenant_user'),
    )
    op.create_index(
        op.f('ix_tenant_members_tenant_id'), 'tenant_members', ['tenant_id'], unique=False
    )
    op.create_index(
        op.f('ix_tenant_members_user_id'), 'tenant_members', ['user_id'], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_tenant_members_user_id'), table_name='tenant_members')
    op.drop_index(op.f('ix_tenant_members_tenant_id'), table_name='tenant_members')
    op.drop_table('tenant_members')

    op.drop_index(
        op.f('ix_password_reset_tokens_token_hash'), table_name='password_reset_tokens'
    )
    op.drop_index(
        op.f('ix_password_reset_tokens_user_id'), table_name='password_reset_tokens'
    )
    op.drop_table('password_reset_tokens')
