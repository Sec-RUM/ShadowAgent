"""Probe for Broken Access Control on the intercept-log API.

This script performs a read-only request that an unauthenticated attacker would
try first: GET /api/v1/logs. It reports whether sensitive audit data is exposed.

Run:
    python backend/broken_access_control_probe.py --base-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
from typing import Any

import httpx


def preview(value: str, max_chars: int = 120) -> str:
    compact = " ".join(value.split())
    if len(compact) <= max_chars:
        return compact
    return compact[:max_chars] + "...[truncated]"


def print_leaked_items(items: list[dict[str, Any]]) -> None:
    if not items:
        print("The endpoint returned 200 OK, but no log rows were present.")
        return

    print(f"Leaked {len(items)} log item(s). Sample:")
    for item in items[:5]:
        details = item.get("details") or {}
        print(
            "- "
            f"id={item.get('id')} "
            f"type={item.get('threat_type')} "
            f"action={item.get('action_taken')} "
            f"layer={details.get('layer', 'unknown')} "
            f"prompt={preview(str(item.get('original_prompt', '')))!r}"
        )


def probe(base_url: str, limit: int, api_key: str | None) -> int:
    headers = {"x-api-key": api_key} if api_key else {}
    target = f"{base_url.rstrip('/')}/api/v1/logs"

    try:
        response = httpx.get(
            target,
            params={"limit": limit},
            headers=headers,
            timeout=10,
        )
    except httpx.HTTPError as exc:
        print(f"Request failed: {exc}")
        return 2

    print(f"GET {response.url}")
    print(f"HTTP {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        items = data.get("items", [])
        if api_key:
            print("Authorized control request succeeded.")
            print_leaked_items(items)
            return 0

        print("VULNERABLE: unauthenticated access can read intercept logs.")
        print_leaked_items(items)
        return 1

    if response.status_code in (401, 403):
        print("Protected: unauthenticated access was denied.")
        return 0

    if response.status_code == 429:
        print("Protected by rate limiting for this client/window.")
        return 0

    print("Unexpected response body:")
    print(response.text[:1000])
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Broken Access Control probe for Shadow Agent logs.",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument(
        "--api-key",
        help="Optional admin API key for a positive-control authorized request.",
    )
    args = parser.parse_args()

    return probe(args.base_url, args.limit, args.api_key)


if __name__ == "__main__":
    raise SystemExit(main())
