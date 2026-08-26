"""Database configuration for Shadow Agent."""

from __future__ import annotations

import os
from pathlib import Path
from threading import Lock
from typing import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


def _configured_database_url() -> str:
    explicit_url = os.getenv("SHADOW_AGENT_DATABASE_URL", "").strip()
    if explicit_url:
        return explicit_url

    configured_path = os.getenv("SHADOW_AGENT_DATABASE_PATH", "").strip()
    if configured_path:
        database_path = Path(configured_path)
        if not database_path.is_absolute():
            database_path = Path(__file__).resolve().parent / database_path
    else:
        database_path = Path(__file__).resolve().parent / "shadow_agent.db"

    return f"sqlite:///{database_path.resolve().as_posix()}"


DATABASE_URL = _configured_database_url()


class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)


if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _configure_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
        """WAL + busy timeout so request writes and audit writes coexist."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

_init_lock = Lock()


def init_database() -> None:
    with _init_lock:
        import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        _apply_lightweight_migrations()
        _backfill_intercept_log_request_ids()


def _backfill_intercept_log_request_ids() -> None:
    """Backfill request_id for legacy rows that only carry it inside details JSON."""
    import json

    from models import InterceptLog

    db = SessionLocal()
    try:
        chunk_size = 200
        last_id = 0
        while True:
            rows = (
                db.query(InterceptLog)
                .filter(
                    InterceptLog.id > last_id,
                    InterceptLog.request_id == "",
                )
                .order_by(InterceptLog.id.asc())
                .limit(chunk_size)
                .all()
            )
            if not rows:
                break
            for row in rows:
                last_id = row.id
                try:
                    details = json.loads(row.details)
                except (TypeError, ValueError):
                    continue
                if not isinstance(details, dict):
                    continue
                request_id = details.get("request_id")
                if isinstance(request_id, str) and request_id.strip():
                    row.request_id = request_id.strip()[:96]
            db.commit()
    finally:
        db.close()


def _apply_lightweight_migrations() -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as connection:
        if "security_policies" in existing_tables:
            policy_columns = {column["name"] for column in inspector.get_columns("security_policies")}
            if "severity" not in policy_columns:
                connection.execute(
                    text(
                        "ALTER TABLE security_policies ADD COLUMN severity VARCHAR(32) NOT NULL DEFAULT 'medium'"
                    )
                )
            if "scope" not in policy_columns:
                connection.execute(
                    text(
                        "ALTER TABLE security_policies ADD COLUMN scope VARCHAR(64) NOT NULL DEFAULT 'Prompt'"
                    )
                )
            if "system_managed" not in policy_columns:
                connection.execute(
                    text(
                        "ALTER TABLE security_policies ADD COLUMN system_managed BOOLEAN NOT NULL DEFAULT 0"
                    )
                )

        if "tool_policies" in existing_tables:
            tool_columns = {column["name"] for column in inspector.get_columns("tool_policies")}
            if "system_managed" not in tool_columns:
                connection.execute(
                    text(
                        "ALTER TABLE tool_policies ADD COLUMN system_managed BOOLEAN NOT NULL DEFAULT 0"
                    )
                )

        if "intercept_logs" in existing_tables:
            log_columns = {column["name"] for column in inspector.get_columns("intercept_logs")}
            if "request_id" not in log_columns:
                connection.execute(
                    text(
                        "ALTER TABLE intercept_logs ADD COLUMN request_id VARCHAR(96) NOT NULL DEFAULT ''"
                    )
                )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_intercept_logs_request_id "
                    "ON intercept_logs (request_id)"
                )
            )

        if "approval_requests" in existing_tables:
            approval_columns = {column["name"] for column in inspector.get_columns("approval_requests")}
            if "reviewed_by" not in approval_columns:
                connection.execute(
                    text(
                        "ALTER TABLE approval_requests ADD COLUMN reviewed_by VARCHAR(128) NOT NULL DEFAULT ''"
                    )
                )
            if "review_comment" not in approval_columns:
                connection.execute(
                    text(
                        "ALTER TABLE approval_requests ADD COLUMN review_comment TEXT NOT NULL DEFAULT ''"
                    )
                )

        if "console_users" in existing_tables:
            user_columns = {column["name"] for column in inspector.get_columns("console_users")}
            if "is_active" not in user_columns:
                connection.execute(
                    text(
                        "ALTER TABLE console_users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1"
                    )
                )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
