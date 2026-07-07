"""add notifications and alert rules

Revision ID: a1b3c5d7e9f1
Revises: f6a8b0c2d4e6
Create Date: 2026-07-07 10:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b3c5d7e9f1'
down_revision: Union[str, None] = 'f6a8b0c2d4e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SEVERITY = sa.Enum(
    'CRITICAL', 'WARNING', 'INFO', name='notificationseverity', native_enum=False
)
_CHANNEL = sa.Enum(
    'IN_APP', 'EMAIL', 'SLACK', 'WEBHOOK', name='alertchannel', native_enum=False
)


def upgrade() -> None:
    op.create_table(
        'notifications',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('severity', _SEVERITY, nullable=False),
        sa.Column('category', sa.String(length=40), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=40), nullable=False),
        sa.Column('link', sa.String(length=255), nullable=True),
        sa.Column('is_read', sa.Boolean(), nullable=False),
        sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_notifications_user_id'), 'notifications', ['user_id'], unique=False)
    op.create_index(op.f('ix_notifications_severity'), 'notifications', ['severity'], unique=False)
    op.create_index(op.f('ix_notifications_category'), 'notifications', ['category'], unique=False)
    op.create_index(op.f('ix_notifications_is_read'), 'notifications', ['is_read'], unique=False)

    op.create_table(
        'alert_rules',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('source', sa.String(length=40), nullable=False),
        sa.Column('condition', sa.String(length=255), nullable=False),
        sa.Column('threshold_severity', _SEVERITY, nullable=False),
        sa.Column('channel', _CHANNEL, nullable=False),
        sa.Column('target', sa.String(length=200), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.Column('created_by', sa.String(length=120), nullable=False),
        sa.Column('last_triggered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('trigger_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_alert_rules_name'), 'alert_rules', ['name'], unique=True)
    op.create_index(op.f('ix_alert_rules_source'), 'alert_rules', ['source'], unique=False)
    op.create_index(op.f('ix_alert_rules_is_enabled'), 'alert_rules', ['is_enabled'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_alert_rules_is_enabled'), table_name='alert_rules')
    op.drop_index(op.f('ix_alert_rules_source'), table_name='alert_rules')
    op.drop_index(op.f('ix_alert_rules_name'), table_name='alert_rules')
    op.drop_table('alert_rules')
    op.drop_index(op.f('ix_notifications_is_read'), table_name='notifications')
    op.drop_index(op.f('ix_notifications_category'), table_name='notifications')
    op.drop_index(op.f('ix_notifications_severity'), table_name='notifications')
    op.drop_index(op.f('ix_notifications_user_id'), table_name='notifications')
    op.drop_table('notifications')
