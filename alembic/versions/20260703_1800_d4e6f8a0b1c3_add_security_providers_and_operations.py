"""add security_providers and security_operations

Revision ID: d4e6f8a0b1c3
Revises: c3d5e7f9a1b2
Create Date: 2026-07-03 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e6f8a0b1c3'
down_revision: Union[str, None] = 'c3d5e7f9a1b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'security_providers',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column(
            'provider_type',
            sa.Enum('PKCS11', 'CLOUD_KMS', 'SOFTWARE', name='securityprovidertype', native_enum=False),
            nullable=False,
        ),
        sa.Column('model', sa.String(length=60), nullable=False),
        sa.Column('manufacturer', sa.String(length=60), nullable=False),
        sa.Column('library_path', sa.String(length=200), nullable=True),
        sa.Column('firmware_version', sa.String(length=40), nullable=True),
        sa.Column('serial_number', sa.String(length=40), nullable=True),
        sa.Column('fips_level', sa.String(length=40), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('pool_active', sa.Integer(), nullable=False),
        sa.Column('pool_max', sa.Integer(), nullable=False),
        sa.Column('connection_timeout_seconds', sa.Integer(), nullable=False),
        sa.Column('avg_latency_ms', sa.Float(), nullable=False),
        sa.Column('session_count', sa.Integer(), nullable=False),
        sa.Column('rw_session_count', sa.Integer(), nullable=False),
        sa.Column('error_count_24h', sa.Integer(), nullable=False),
        sa.Column('supported_mechanisms', sa.JSON(), nullable=False),
        sa.Column('last_health_check_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    op.create_table(
        'security_operations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column(
            'operation_type',
            sa.Enum(
                'KEY_CREATE',
                'KEY_ROTATE',
                'KEY_DISABLE',
                'ATTESTATION_RUN',
                'CEREMONY_COMPLETE',
                name='securityoperationtype',
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column('master_key_id', sa.UUID(), nullable=True),
        sa.Column('key_label', sa.String(length=80), nullable=True),
        sa.Column('actor', sa.String(length=120), nullable=False),
        sa.Column(
            'status',
            sa.Enum('SUCCESS', 'FAILED', name='securityoperationstatus', native_enum=False),
            nullable=False,
        ),
        sa.Column('detail', sa.String(length=300), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['master_key_id'], ['master_keys.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_security_operations_operation_type'),
        'security_operations',
        ['operation_type'],
        unique=False,
    )
    op.create_index(
        op.f('ix_security_operations_occurred_at'),
        'security_operations',
        ['occurred_at'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_security_operations_occurred_at'),
        table_name='security_operations',
    )
    op.drop_index(
        op.f('ix_security_operations_operation_type'),
        table_name='security_operations',
    )
    op.drop_table('security_operations')
    op.drop_table('security_providers')
