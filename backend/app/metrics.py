"""Dependency-free Prometheus exposition metrics for the gateway.

Collects per-route request counters and latency histograms in-process.
Cardinality stays bounded because paths are normalized to route templates
(``/api/v1/logs``) or digit-collapsed fallbacks (``/api/v1/policies/{id}``).
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from security_controls import Principal, require_admin

LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)
_DIGIT_SEGMENTS = re.compile(r"/\d+(/|$)")

_lock = threading.Lock()
_request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
_latency_buckets: dict[tuple[str, float], int] = defaultdict(int)
_latency_sums: dict[str, float] = defaultdict(float)
_latency_counts: dict[str, int] = defaultdict(int)
_retention_purged: dict[str, int] = defaultdict(int)


def record_retention_purged(table: str, count: int) -> None:
    """Track rows removed by the retention cleanup job (see app/retention.py)."""
    if count <= 0:
        return
    with _lock:
        _retention_purged[table] += count

router = APIRouter(tags=["metrics"])


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record request count and latency for every served request."""

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        status_code = 500
        route_template = _route_template(request)
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            if route_template != "/metrics":
                elapsed = time.perf_counter() - started
                _record(route_template, request.method, status_code, elapsed)


def _route_template(request: Request) -> str:
    """Prefer the matched route template; collapse numeric ids otherwise."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if isinstance(path, str) and path:
        return path
    raw_path = request.url.path
    return _DIGIT_SEGMENTS.sub("/{id}\\1", raw_path)


def _record(route: str, method: str, status_code: int, elapsed: float) -> None:
    with _lock:
        _request_counts[(method, str(status_code), route)] += 1
        _latency_counts[route] += 1
        _latency_sums[route] += elapsed
        for bucket in LATENCY_BUCKETS:
            if elapsed <= bucket:
                _latency_buckets[(route, bucket)] += 1
                break
        _latency_buckets[(route, float("inf"))] += 1


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics() -> str:
    """Render counters/histograms in Prometheus text exposition format."""
    lines: list[str] = []

    with _lock:
        request_snapshot = dict(_request_counts)
        bucket_snapshot = dict(_latency_buckets)
        sum_snapshot = dict(_latency_sums)
        count_snapshot = dict(_latency_counts)
        retention_snapshot = dict(_retention_purged)

    lines.append("# HELP shadow_agent_http_requests_total Total HTTP requests handled.")
    lines.append("# TYPE shadow_agent_http_requests_total counter")
    for (method, status, route), count in sorted(request_snapshot.items()):
        lines.append(
            'shadow_agent_http_requests_total{method="%s",status="%s",route="%s"} %d'
            % (_escape_label(method), _escape_label(status), _escape_label(route), count)
        )

    lines.append("# HELP shadow_agent_http_request_duration_seconds HTTP request latency.")
    lines.append("# TYPE shadow_agent_http_request_duration_seconds histogram")
    routes = sorted(set(count_snapshot) | {route for route, _ in bucket_snapshot})
    for route in routes:
        for bucket in LATENCY_BUCKETS:
            lines.append(
                'shadow_agent_http_request_duration_seconds_bucket{route="%s",le="%s"} %d'
                % (_escape_label(route), _format_le(bucket), bucket_snapshot.get((route, bucket), 0))
            )
        lines.append(
            'shadow_agent_http_request_duration_seconds_bucket{route="%s",le="+Inf"} %d'
            % (_escape_label(route), bucket_snapshot.get((route, float("inf")), 0))
        )
        lines.append(
            'shadow_agent_http_request_duration_seconds_sum{route="%s"} %.6f'
            % (_escape_label(route), sum_snapshot.get(route, 0.0))
        )
        lines.append(
            'shadow_agent_http_request_duration_seconds_count{route="%s"} %d'
            % (_escape_label(route), count_snapshot.get(route, 0))
        )

    lines.append("# HELP shadow_agent_retention_purged_rows_total Rows purged by the retention job.")
    lines.append("# TYPE shadow_agent_retention_purged_rows_total counter")
    for table, count in sorted(retention_snapshot.items()):
        lines.append(
            'shadow_agent_retention_purged_rows_total{table="%s"} %d'
            % (_escape_label(table), count)
        )

    lines.append("")
    return "\n".join(lines)


def _format_le(bucket: float) -> str:
    text = f"{bucket:g}"
    return text


@router.get("/metrics")
async def metrics_endpoint(
    principal: Principal = Depends(require_admin),
) -> Response:
    """Prometheus scrape endpoint (admin credentials required)."""
    return Response(
        content=render_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


def metrics_snapshot() -> dict[str, Any]:
    """Structured snapshot for diagnostics/tests."""
    with _lock:
        return {
            "requests": {
                f"{method}|{status}|{route}": count
                for (method, status, route), count in _request_counts.items()
            },
            "latency_counts": dict(_latency_counts),
            "latency_sums": {k: round(v, 6) for k, v in _latency_sums.items()},
        }
