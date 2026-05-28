"""Lightweight local .env loader for development."""

from __future__ import annotations

import os
from pathlib import Path


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _load_env_file(path: Path) -> None:
    if not path.is_file():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        if line.startswith("export "):
            line = line[7:].strip()

        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue

        os.environ[key] = _strip_quotes(value.strip())


def load_local_env() -> None:
    base_dir = Path(__file__).resolve().parent
    for candidate in (
        base_dir / ".env",
        base_dir / ".env.local",
        base_dir.parent / ".env",
    ):
        _load_env_file(candidate)
