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
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
