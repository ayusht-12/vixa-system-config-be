"""Pytest fixtures for the vsc-be test suite.

Tests run against a real Postgres database (a separate `vsc_be_test`
database on the same server as local dev) rather than SQLite, because the
schema leans on Postgres-specific constructs — the `sequence` IDENTITY
column, JSON columns, dialect UUID type — that SQLite can't reproduce
faithfully. Tables are created directly from the SQLAlchemy metadata
(`Base.metadata.create_all`) rather than via Alembic for speed; the
migrations themselves (including the hand-written audit-log immutability
trigger) are exercised separately by running `alembic upgrade head`
against a real environment, not by this suite.
"""

import os
import uuid

os.environ.setdefault("POSTGRES_DB", "vsc_be_test")
os.environ.setdefault("AUDIT_SIGNING_KEY_PATH", "./var/test_audit_signing_key.pem")

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.core.config import settings
from app.core.security import hash_password
from app.db.base import Base
from app.main import app
from app.models.user import User


@pytest_asyncio.fixture
async def engine():
    # Function-scoped with NullPool: pytest-asyncio gives every test its own
    # event loop by default, and asyncpg connections can't be reused across
    # loops, so each test gets a fresh engine/connection rather than sharing
    # a session-scoped one.
    test_engine = create_async_engine(str(settings.DATABASE_URL), poolclass=NullPool)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield test_engine
    await test_engine.dispose()


@pytest_asyncio.fixture
async def db_session(engine):
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(table.delete())
        await session.commit()


@pytest_asyncio.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email="test@nexus.local",
        display_name="Test User",
        hashed_password=hash_password("TestPassword!123"),
        is_active=True,
        is_admin=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user
