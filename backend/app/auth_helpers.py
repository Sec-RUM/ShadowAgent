"""Auth/session helpers and console registration policy."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import ALLOWED_PLATFORM_ROLES, _env_text
from app.schemas import AuthSessionResponse, AuthUserResponse
from app.utils import _utc_timestamp
from models import ConsoleUser
from security_controls import Principal, create_jwt, hash_password

# Pre-computed hash used to equalize login timing when the account does not
# exist, preventing account enumeration through response-time differences.
_DUMMY_PASSWORD_HASH = hash_password("shadow-agent-timing-equalizer")


def _normalize_console_role(role: str | None, fallback: str) -> str:
    normalized = (role or "").strip().lower()
    if normalized in ALLOWED_PLATFORM_ROLES:
        return normalized
    return fallback


def _require_platform_role(role: str) -> str:
    normalized = (role or "").strip().lower()
    if normalized in ALLOWED_PLATFORM_ROLES:
        return normalized
    raise HTTPException(
        status_code=400,
        detail={
            "error": "invalid_role",
            "message": (
                "Role must be one of: admin, security_admin, client, gateway."
            ),
        },
    )


def _console_registration_role(db: Session) -> str:
    console_user_count = db.query(ConsoleUser.id).count()
    if console_user_count == 0:
        return _normalize_console_role(_env_text("SHADOW_AGENT_FIRST_USER_ROLE"), "admin")
    return _normalize_console_role(_env_text("SHADOW_AGENT_CONSOLE_DEFAULT_ROLE"), "client")


def _serialize_console_user(user: ConsoleUser) -> dict[str, Any]:
    return AuthUserResponse(
        id=str(user.id),
        name=user.name,
        email=user.email,
        role=user.role,
        created_at=_utc_timestamp(user.created_at) or "",
    ).model_dump()


def _auth_session_payload(user: ConsoleUser) -> dict[str, Any]:
    token, expires_at = create_jwt(
        subject=f"console-user:{user.id}",
        role=user.role,
        extra_claims={"email": user.email, "name": user.name, "user_type": "console"},
    )
    return AuthSessionResponse(
        access_token=token,
        token_type="bearer",
        expires_at=expires_at,
        user=AuthUserResponse(
            id=str(user.id),
            name=user.name,
            email=user.email,
            role=user.role,
            created_at=_utc_timestamp(user.created_at) or "",
        ),
    ).model_dump()


def _principal_user_id(principal: Principal) -> int | None:
    prefix = "console-user:"
    if principal.subject.startswith(prefix):
        try:
            return int(principal.subject[len(prefix):])
        except ValueError:
            return None
    return None


def _principal_label(principal: Principal, db: Session | None = None) -> str:
    user_id = _principal_user_id(principal)
    if user_id is None or db is None:
        return principal.subject

    user = db.query(ConsoleUser).filter(ConsoleUser.id == user_id).one_or_none()
    if user is None:
        return principal.subject
    return user.email
