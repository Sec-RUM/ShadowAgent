"""Authentication, rate limiting, and redaction helpers for Shadow Agent."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param


ADMIN_ROLES = {"admin", "security_admin"}
CLIENT_ROLES = ADMIN_ROLES | {"client", "gateway"}
SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "cookie",
    "password",
    "refresh_token",
    "secret",
    "token",
}
SENSITIVE_TEXT_PATTERNS = [
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password)"
        r"\s*[:=]\s*['\"]?([^\s,'\"}]+)"
    ),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}"),
]
REQUEST_ID_PATTERN = re.compile(r"[^a-zA-Z0-9_.:-]")


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    role: str
    auth_method: str


class InMemoryRateLimiter:
    """Small fixed-window limiter for local/prototype deployments."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

        if len(bucket) >= limit:
            retry_after = max(1, int(window_seconds - (now - bucket[0])))
            return False, retry_after

        bucket.append(now)
        return True, 0


rate_limiter = InMemoryRateLimiter()


def _env_secret(name: str) -> str | None:
    value = os.getenv(name)
    if value and value.strip():
        return value.strip()
    return None


def _unauthorized(message: str = "Authentication required.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "unauthorized", "message": message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(message: str = "Insufficient permissions.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error": "forbidden", "message": message},
    )


def _auth_not_configured() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "auth_not_configured",
            "message": (
                "Set SHADOW_AGENT_ADMIN_API_KEY, SHADOW_AGENT_CLIENT_API_KEY, "
                "or SHADOW_AGENT_JWT_SECRET before using protected endpoints."
            ),
        },
    )


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _verify_jwt(token: str) -> Principal | None:
    secret = _env_secret("SHADOW_AGENT_JWT_SECRET")
    if not secret:
        return None
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "weak_jwt_secret",
                "message": "SHADOW_AGENT_JWT_SECRET must be at least 32 characters.",
            },
        )

    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except (binascii.Error, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise _unauthorized("Malformed JWT.")

    if header.get("alg") != "HS256" or header.get("typ") not in (None, "JWT"):
        raise _unauthorized("Unsupported JWT header.")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise _unauthorized("Invalid JWT signature.")

    now = int(time.time())
    try:
        expires_at = int(payload["exp"])
        not_before = int(payload["nbf"]) if "nbf" in payload else None
    except (KeyError, TypeError, ValueError):
        raise _unauthorized("JWT must include numeric exp and optional numeric nbf.")

    if expires_at < now:
        raise _unauthorized("JWT has expired.")
    if not_before is not None and not_before > now:
        raise _unauthorized("JWT is not valid yet.")

    role = str(payload.get("role", "client"))
    subject = str(payload.get("sub", "jwt-subject"))
    return Principal(subject=subject, role=role, auth_method="jwt")


def _verify_api_key(request: Request) -> Principal | None:
    presented = (
        request.headers.get("x-api-key")
        or request.headers.get("x-admin-api-key")
        or request.headers.get("x-client-api-key")
    )
    if not presented:
        return None

    admin_key = _env_secret("SHADOW_AGENT_ADMIN_API_KEY")
    client_key = _env_secret("SHADOW_AGENT_CLIENT_API_KEY")

    if admin_key and hmac.compare_digest(presented, admin_key):
        return Principal(subject="api-key-admin", role="admin", auth_method="api_key")
    if client_key and hmac.compare_digest(presented, client_key):
        return Principal(subject="api-key-client", role="client", auth_method="api_key")

    raise _unauthorized("Invalid API key.")


def _authenticate(request: Request) -> Principal:
    authorization = request.headers.get("authorization")
    scheme, credentials = get_authorization_scheme_param(authorization)

    if scheme.lower() == "bearer" and credentials:
        principal = _verify_jwt(credentials)
        if principal:
            return principal

    principal = _verify_api_key(request)
    if principal:
        return principal

    if any(
        _env_secret(name)
        for name in (
            "SHADOW_AGENT_ADMIN_API_KEY",
            "SHADOW_AGENT_CLIENT_API_KEY",
            "SHADOW_AGENT_JWT_SECRET",
        )
    ):
        raise _unauthorized()
    raise _auth_not_configured()


async def require_admin(request: Request) -> Principal:
    principal = _authenticate(request)
    if principal.role not in ADMIN_ROLES:
        raise _forbidden("Admin role required.")
    return principal


async def require_client(request: Request) -> Principal:
    principal = _authenticate(request)
    if principal.role not in CLIENT_ROLES:
        raise _forbidden("Gateway client role required.")
    return principal


def sanitize_request_id(value: str | None) -> str:
    if not value:
        return ""
    return REQUEST_ID_PATTERN.sub("-", value)[:96]


def redact_text(value: str, max_chars: int = 4000) -> str:
    redacted = value
    for pattern in SENSITIVE_TEXT_PATTERNS:
        redacted = pattern.sub(
            lambda match: (
                f"{match.group(1)}=<redacted>"
                if match.lastindex
                else "Bearer <redacted>"
            ),
            redacted,
        )
    if len(redacted) > max_chars:
        return redacted[:max_chars] + "...[truncated]"
    return redacted


def sanitize_json(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "<max_depth>"
    if isinstance(value, str):
        return redact_text(value, max_chars=1000)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS:
                sanitized[key_text] = "<redacted>"
            else:
                sanitized[key_text] = sanitize_json(item, depth + 1)
        return sanitized
    if isinstance(value, list):
        return [sanitize_json(item, depth + 1) for item in value[:50]]
    return value


async def rate_limit_middleware(request: Request, call_next: Any) -> Any:
    if request.url.path.startswith("/api/"):
        default_limit = int(os.getenv("SHADOW_AGENT_RATE_LIMIT_PER_MINUTE", "60"))
        logs_limit = int(os.getenv("SHADOW_AGENT_LOG_RATE_LIMIT_PER_MINUTE", "20"))
        limit = logs_limit if request.url.path == "/api/v1/logs" else default_limit
        client_host = request.client.host if request.client else "unknown"
        key = f"{client_host}:{request.method}:{request.url.path}"

        allowed, retry_after = rate_limiter.check(key, max(1, limit), 60)
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limited",
                    "message": "Too many requests. Try again later.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

    return await call_next(request)
