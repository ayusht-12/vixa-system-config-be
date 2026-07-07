"""add operations tables (background jobs, application errors)

Revision ID: b2c4d6e8f0a2
Revises: a1b3c5d7e9f1
Create Date: 2026-07-07 10:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c4d6e8f0a2'
down_revision: Union[str, None] = 'a1b3c5d7e9f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JOB_STATUS = sa.Enum(
    'QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', name='jobstatus', native_enum=False
)
_ERROR_LEVEL = sa.Enum(
    'CRITICAL', 'ERROR', 'WARNING', name='errorlevel', native_enum=False
)


def upgrade() -> None:
    op.create_table(
        'background_jobs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('queue', sa.String(length=60), nullable=False),
        sa.Column('status', _JOB_STATUS, nullable=False),
        sa.Column('progress_percent', sa.Float(), nullable=False),
        sa.Column('scheduled_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_ms', sa.Float(), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('max_attempts', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.String(length=255), nullable=True),
        sa.Column('detail', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_background_jobs_name'), 'background_jobs', ['name'], unique=False)
    op.create_index(op.f('ix_background_jobs_status'), 'background_jobs', ['status'], unique=False)

    op.create_table(
        'application_errors',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('level', _ERROR_LEVEL, nullable=False),
        sa.Column('error_type', sa.String(length=120), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=120), nullable=False),
        sa.Column('request_path', sa.String(length=200), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('occurrences', sa.Integer(), nullable=False),
        sa.Column('resolved', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_application_errors_occurred_at'), 'application_errors', ['occurred_at'], unique=False
    )
    op.create_index(
        op.f('ix_application_errors_level'), 'application_errors', ['level'], unique=False
    )
    op.create_index(
        op.f('ix_application_errors_resolved'), 'application_errors', ['resolved'], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_application_errors_resolved'), table_name='application_errors')
    op.drop_index(op.f('ix_application_errors_level'), table_name='application_errors')
    op.drop_index(op.f('ix_application_errors_occurred_at'), table_name='application_errors')
    op.drop_table('application_errors')
    op.drop_index(op.f('ix_background_jobs_status'), table_name='background_jobs')
    op.drop_index(op.f('ix_background_jobs_name'), table_name='background_jobs')
    op.drop_table('background_jobs')
