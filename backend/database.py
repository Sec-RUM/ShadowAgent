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

        _apply_org_tenancy_columns(connection, inspector, existing_tables)


def _apply_org_tenancy_columns(connection, inspector, existing_tables) -> None:
    """Lightweight multi-tenancy migration for pre-Alembic databases.

    Fresh databases get everything from ``Base.metadata.create_all``; this
    only patches tables that already existed without ``org_id``.
    """
    for table in (
        "intercept_logs",
        "audit_logs",
        "security_policies",
        "approval_requests",
        "alert_events",
        "replay_runs",
        "managed_api_keys",
        "tool_policies",
    ):
        if table not in existing_tables:
            continue
        columns = {column["name"] for column in inspector.get_columns(table)}
        if "org_id" not in columns:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN org_id INTEGER"))
        connection.execute(
            text(f"CREATE INDEX IF NOT EXISTS ix_{table}_org_id ON {table} (org_id)")
        )

    if "tool_policies" in existing_tables:
        # Replace the global tool_name unique index with the per-organization
        # (org_id, tool_name) one so tenants can override shared defaults.
        index_names = {index["name"] for index in inspector.get_indexes("tool_policies")}
        if "ix_tool_policies_tool_name" in index_names:
            connection.execute(text("DROP INDEX ix_tool_policies_tool_name"))
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_tool_policy_org_tool "
                "ON tool_policies (org_id, tool_name)"
            )
        )

    if "custom_rules" in existing_tables:
        _apply_custom_rules_tenancy(connection, inspector)


def _apply_custom_rules_tenancy(connection, inspector) -> None:
    """custom_rules: org_id column + per-organization (org_id, name) uniqueness.

    The baseline schema enforced globally-unique rule names with an inline
    table constraint. SQLite implements it as an ``sqlite_autoindex`` that
    cannot be dropped in place, so the table is rebuilt; on Postgres the
    named constraint is dropped directly.
    """
    columns = {column["name"] for column in inspector.get_columns("custom_rules")}
    unique_constraints = inspector.get_unique_constraints("custom_rules")
    legacy_name_unique = any(
        [str(column).lower() for column in constraint.get("column_names", [])] == ["name"]
        for constraint in unique_constraints
    )

    if legacy_name_unique or "org_id" not in columns:
        if engine.dialect.name == "sqlite":
            _rebuild_custom_rules_sqlite(connection, has_org_id="org_id" in columns)
        else:
            if legacy_name_unique:
                connection.execute(
                    text("ALTER TABLE custom_rules DROP CONSTRAINT IF EXISTS custom_rules_name_key")
                )
            if "org_id" not in columns:
                connection.execute(text("ALTER TABLE custom_rules ADD COLUMN org_id INTEGER"))

    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_custom_rules_org_id ON custom_rules (org_id)")
    )
    connection.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_custom_rule_org_name "
            "ON custom_rules (org_id, name)"
        )
    )


def _rebuild_custom_rules_sqlite(connection, *, has_org_id: bool) -> None:
    """Rebuild custom_rules on SQLite: adds org_id and drops the legacy
    global UNIQUE(name) autoindex (renaming loses dependent indexes too)."""
    connection.execute(text("ALTER TABLE custom_rules RENAME TO custom_rules_legacy_tenancy"))
    connection.execute(
        text(
            """
            CREATE TABLE custom_rules (
                id INTEGER NOT NULL,
                org_id INTEGER,
                name VARCHAR(128) NOT NULL,
                description TEXT NOT NULL,
                rule_type VARCHAR(16) NOT NULL,
                pattern VARCHAR(512) NOT NULL,
                target VARCHAR(16) NOT NULL,
                action VARCHAR(16) NOT NULL,
                risk_score FLOAT NOT NULL,
                enabled BOOLEAN NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id)
            )
            """
        )
    )
    org_source = "org_id" if has_org_id else "NULL"
    connection.execute(
        text(
            "INSERT INTO custom_rules (id, org_id, name, description, rule_type, "
            "pattern, target, action, risk_score, enabled, created_at, updated_at) "
            f"SELECT id, {org_source}, name, description, rule_type, pattern, "
            "target, action, risk_score, enabled, created_at, updated_at "
            "FROM custom_rules_legacy_tenancy"
        )
    )
    connection.execute(text("DROP TABLE custom_rules_legacy_tenancy"))
    for index_column in ("id", "name", "rule_type", "target", "action", "enabled"):
        connection.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS ix_custom_rules_{index_column} "
                f"ON custom_rules ({index_column})"
            )
        )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
