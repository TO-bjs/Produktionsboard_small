"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-27
"""
from alembic import op
import sqlalchemy as sa


revision = '0001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('username', sa.Text(), nullable=False, unique=True),
        sa.Column('password_hash', sa.Text(), nullable=False),
        sa.Column('email', sa.Text(), nullable=False),
        sa.Column('is_admin', sa.Integer(), server_default='0'),
    )
    op.create_table(
        'reset_tokens',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )
    op.create_table(
        'trainings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('date', sa.Text(), nullable=False),
        sa.Column('time', sa.Text()),
        sa.Column('participants', sa.Text()),
        sa.Column('status', sa.Text(), server_default='geplant'),
    )
    op.create_table(
        'announcements',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('source', sa.Text()),
        sa.Column('attachment_path', sa.Text()),
        sa.Column('expires_at', sa.DateTime()),
        sa.Column('created_by', sa.Integer()),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
    )


def downgrade() -> None:
    op.drop_table('announcements')
    op.drop_table('trainings')
    op.drop_table('reset_tokens')
    op.drop_table('users')
