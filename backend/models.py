"""SQLAlchemy models for Shadow Agent."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class InterceptLog(Base):
    __tablename__ = "intercept_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_taken: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    original_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    original_instruction: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    triggered_rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    intercept_reason: Mapped[str] = mapped_column(Text, nullable=False)


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    blacklist_keyword: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    scope: Mapped[str] = mapped_column(String(64), default="Prompt", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    system_managed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )


class ToolPolicy(Base):
    __tablename__ = "tool_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tool_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
    )
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    requires_admin_approval: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    system_managed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommended_action: Mapped[str] = mapped_column(String(32), default="block", nullable=False)
    original_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    categories: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    details: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    reviewed_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    review_comment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(32), default="console", nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="triggered", nullable=False, index=True)
    details: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )


class ReplayRun(Base):
    __tablename__ = "replay_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    replay_request_id: Mapped[str] = mapped_column(String(96), nullable=False, unique=True, index=True)
    triggered_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False, index=True)
    risk_score: Mapped[str] = mapped_column(String(32), default="0", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="none", nullable=False, index=True)
    details: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )


class ConsoleUser(Base):
    __tablename__ = "console_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="admin", nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
