"""Small shared pure helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone


def _json_loads_safe(value: str, fallback):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _utc_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None

    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).isoformat()


def _normalized_email(value: str) -> str:
    return value.strip().lower()
