"""Pool-sizing rules for the request path (see `database._pool_kwargs`).

These are pure, deterministic checks: the default QueuePool ceiling (5+10=15)
used to stall the whole event loop at ~32 concurrent clients, and in-memory
SQLite must NOT receive sizing arguments (SingletonThreadPool rejects them).

Run from backend/: python -m pytest tests/test_db_pool.py -v
"""

from __future__ import annotations

import pytest

from database import _pool_kwargs

SIZED = {"pool_size": 20, "max_overflow": 40, "pool_timeout": 5}


def test_file_sqlite_is_sized_above_the_default_ceiling() -> None:
    kwargs = _pool_kwargs("sqlite:///C:/tmp/shadow_agent.db")
    assert kwargs == SIZED
    # Ceiling must comfortably exceed the concurrency at which the old default
    # (15 connections) blocked the event loop.
    assert kwargs["pool_size"] + kwargs["max_overflow"] > 32


def test_pool_timeout_is_short_enough_to_fail_fast() -> None:
    # 30s (the SQLAlchemy default) pins the event loop; saturation must surface
    # as an error quickly instead.
    assert _pool_kwargs("sqlite:///tmp/x.db")["pool_timeout"] <= 10


def test_postgres_urls_are_sized_too() -> None:
    assert _pool_kwargs("postgresql+psycopg://u:p@localhost/shadow") == SIZED


@pytest.mark.parametrize(
    "url",
    ["sqlite://", "sqlite:///", "sqlite:///:memory:", "sqlite+pysqlite:///:memory:"],
)
def test_in_memory_sqlite_is_left_alone(url: str) -> None:
    # SingletonThreadPool raises TypeError on pool_size/max_overflow.
    assert _pool_kwargs(url) == {}


def test_engine_actually_received_the_sizing() -> None:
    """Guard against the kwargs being computed but never passed to create_engine."""
    from database import DATABASE_URL, engine

    if _pool_kwargs(DATABASE_URL):
        pool = engine.pool
        assert pool.size() == 20
        assert pool._max_overflow == 40
