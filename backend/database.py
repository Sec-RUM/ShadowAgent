"""Database configuration for Shadow Agent."""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


DATABASE_PATH = Path(__file__).resolve().parent / "shadow_agent.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"


class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

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
