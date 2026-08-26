"""Console authentication: bootstrap, register, login, session introspection."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import _record_auth_event
from app.auth_helpers import (
    _DUMMY_PASSWORD_HASH,
    _auth_session_payload,
    _console_registration_role,
    _normalize_console_role,
    _principal_user_id,
    _serialize_console_user,
)
from app.config import (
    _allow_open_console_bootstrap,
    _allow_open_registration,
    _console_bootstrap_required,
    _console_bootstrap_status,
    _console_bootstrap_token,
    _console_invite_token,
    _login_lockout_seconds,
    _login_max_failures,
)
from app.schemas import AuthLoginRequest, AuthRegisterRequest
from app.utils import _normalized_email
from database import get_db
from models import ConsoleUser
from security_controls import (
    Principal,
    hash_password,
    login_throttle,
    require_client,
    verify_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get("/bootstrap-status")
async def get_console_bootstrap_status(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _console_bootstrap_status(db)


@router.post("/register")
async def register_console_user(
    payload: AuthRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    email = _normalized_email(payload.email)
    existing = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={"error": "email_already_registered", "message": "This email is already registered."},
        )

    bootstrap_required = _console_bootstrap_required(db)
    role = _console_registration_role(db)
    if bootstrap_required:
        bootstrap_token = _console_bootstrap_token()
        provided_bootstrap_token = (
            request.headers.get("x-shadow-agent-bootstrap-token")
            or request.headers.get("x-bootstrap-token")
            or ""
        ).strip()
        if bootstrap_token:
            if not hmac.compare_digest(provided_bootstrap_token, bootstrap_token):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "bootstrap_token_required",
                        "message": (
                            "First console admin registration requires the configured bootstrap token. "
                            "Provide it in X-Shadow-Agent-Bootstrap-Token."
                        ),
                    },
                )
        elif not _allow_open_console_bootstrap():
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "bootstrap_setup_required",
                    "message": (
                        "Console bootstrap is locked. Configure SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN "
                        "or explicitly enable SHADOW_AGENT_ALLOW_OPEN_CONSOLE_BOOTSTRAP=true for local demo-only setup."
                    ),
                },
            )
    else:
        # After the first admin exists, open self-registration is locked down by
        # default. Operators either opt back in explicitly for local demos, or
        # provision a shared invite token that new users must present.
        if not _allow_open_registration():
            invite_token = _console_invite_token()
            provided_invite_token = (
                request.headers.get("x-shadow-agent-invite-token")
                or request.headers.get("x-invite-token")
                or ""
            ).strip()
            if not invite_token:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "registration_disabled",
                        "message": (
                            "Open registration is disabled. Configure "
                            "SHADOW_AGENT_ALLOW_OPEN_REGISTRATION=true for local demos, or set "
                            "SHADOW_AGENT_CONSOLE_INVITE_TOKEN and require new users to provide "
                            "it in X-Shadow-Agent-Invite-Token."
                        ),
                    },
                )
            if not hmac.compare_digest(provided_invite_token, invite_token):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "invite_token_required",
                        "message": (
                            "Registration requires a valid invite token. "
                            "Provide it in X-Shadow-Agent-Invite-Token."
                        ),
                    },
                )

    user = ConsoleUser(
        name=payload.name.strip(),
        email=email,
        password_hash=hash_password(payload.password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _auth_session_payload(user)


@router.post("/login")
async def login_console_user(
    payload: AuthLoginRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    email = _normalized_email(payload.email)
    max_failures = _login_max_failures()
    lockout_seconds = _login_lockout_seconds()

    lockout_remaining = login_throttle.locked_out_remaining(
        email,
        max_failures=max_failures,
        window_seconds=lockout_seconds,
    )
    if lockout_remaining:
        _record_auth_event(db, "login_locked_out", email)
        db.commit()
        raise HTTPException(
            status_code=429,
            detail={
                "error": "account_locked",
                "message": "Too many failed login attempts. Try again later.",
                "retry_after_seconds": lockout_remaining,
            },
        )

    user = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if user is None:
        # Equalize verification time so account existence cannot be probed.
        verify_password(payload.password, _DUMMY_PASSWORD_HASH)
        login_throttle.record_failure(email, window_seconds=lockout_seconds)
        _record_auth_event(db, "login_failed", email)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "Invalid email or password."},
        )

    if not user.is_active or not verify_password(payload.password, user.password_hash):
        login_throttle.record_failure(email, window_seconds=lockout_seconds)
        _record_auth_event(db, "login_failed", email)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "Invalid email or password."},
        )

    login_throttle.record_success(email)
    _record_auth_event(db, "login_success", email)
    db.commit()
    return _auth_session_payload(user)


@router.get("/me")
async def get_current_console_user(
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    user_id = _principal_user_id(principal)
    if user_id is None:
        raise HTTPException(
            status_code=403,
            detail={"error": "console_auth_required", "message": "Console user token required."},
        )

    user = db.query(ConsoleUser).filter(ConsoleUser.id == user_id, ConsoleUser.is_active.is_(True)).one_or_none()
    if user is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "user_not_found", "message": "Console user does not exist."},
        )

    return {"user": _serialize_console_user(user)}
