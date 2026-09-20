"""Shadow Agent FastAPI gateway — application wiring.

Endpoint logic lives in the ``app`` package:
- ``app.routers``: HTTP routers per domain (auth, api-keys, monitoring,
  replays, policies, tool-policies, gateway).
- ``app.config`` / ``app.schemas`` / ``app.serializers``: configuration,
  request/response models, row serializers.
- ``app.audit`` / ``app.upstream`` / ``app.auth_helpers``: cross-cutting
  audit trail, upstream LLM forwarding, auth session helpers.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import TimeoutError as DatabasePoolTimeout

from env_loader import load_local_env

load_local_env()

from app.audit import audit_log_executor
from app.config import _allowed_origins, _upstream_proxy_enabled
from app.metrics import MetricsMiddleware, router as metrics_router
from app.retention import cleanup_interval_seconds, run_retention_cleanup
from app.routers import (
    api_keys,
    auth,
    gateway,
    monitoring,
    orgs,
    policies,
    replays,
    rules,
    tool_policies,
)
from app import sso
from app.tenancy import ensure_default_organization
from app.upstream import _close_upstream_client
from database import SessionLocal, init_database, record_pool_timeout
from security_controls import rate_limit_middleware, shared_state_backend
from security_engine import (
    ensure_default_security_policies,
    ensure_default_tool_policies,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("shadow_agent.gateway")


async def _retention_cleanup_loop() -> None:
    """Periodically enforce log retention (GDPR data minimization).

    DB work runs in a worker thread so the event loop is never blocked;
    failures never crash the gateway, the next cycle retries.
    """
    interval = cleanup_interval_seconds()
    while True:
        try:
            await asyncio.to_thread(run_retention_cleanup)
        except Exception:
            logger.exception("Log retention cleanup cycle failed; will retry next interval.")
        await asyncio.sleep(interval)


@asynccontextmanager
async def _app_lifespan(app: FastAPI):
    from app import events as event_bus
    from app import alerts as alert_bus

    event_bus.bind_main_loop(asyncio.get_running_loop())
    alert_bus.bind_main_loop(asyncio.get_running_loop())
    retention_task = asyncio.create_task(_retention_cleanup_loop())
    alert_task = asyncio.create_task(alert_bus.alert_dispatcher_loop())
    yield
    retention_task.cancel()
    alert_task.cancel()
    for task in (retention_task, alert_task):
        with contextlib.suppress(asyncio.CancelledError):
            await task
    await _close_upstream_client()
    audit_log_executor.shutdown(wait=True)


app = FastAPI(
    title="Shadow Agent Gateway",
    description="Middleware sandbox prototype for LLM agent runtime security.",
    version="0.2.1",
    lifespan=_app_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(MetricsMiddleware)
app.middleware("http")(rate_limit_middleware)


@app.exception_handler(DatabasePoolTimeout)
async def _database_pool_timeout(_request: Request, _exc: DatabasePoolTimeout) -> JSONResponse:
    """Report connection-pool exhaustion as a capacity fault, not a server bug.

    Unhandled, ``sqlalchemy.exc.TimeoutError`` reaches Starlette's catch-all and
    leaves as HTTP 500 with a full traceback: an operator gets paged for a code
    fault, and the client receives no signal that retrying is safe. Verified on
    2026-09-20 -- with the ceiling forced back to 15, a c=32 burst produced
    ``sqlalchemy.exc.TimeoutError: QueuePool limit of size 5 overflow 10
    reached`` as a bare 500. Answering 503 + Retry-After matches how the rate
    limiter already replies (429 + Retry-After) and tells an OpenAI-compatible
    client to back off.

    This does not make exhaustion harmless; it makes it legible. The capacity
    itself is fixed by a pool ceiling above peak concurrent demand (see
    ``database._pool_kwargs``) and watched via
    ``shadow_agent_db_pool_timeout_total``.
    """
    record_pool_timeout()
    logging.getLogger("shadow_agent.db").error(
        "Connection-pool timeout served as 503: every pooled connection is held. "
        "Raise SHADOW_AGENT_DB_POOL_SIZE / SHADOW_AGENT_DB_MAX_OVERFLOW or lower "
        "client concurrency."
    )
    return JSONResponse(
        status_code=503,
        content={
            "error": "database_pool_exhausted",
            "message": "The gateway is out of database connections. Retry shortly.",
        },
        headers={"Retry-After": "1"},
    )

app.include_router(auth.router)
app.include_router(api_keys.router)
app.include_router(monitoring.router)
app.include_router(replays.router)
app.include_router(policies.router)
app.include_router(tool_policies.router)
app.include_router(rules.router)
app.include_router(orgs.router)
app.include_router(sso.router)
app.include_router(gateway.router)
app.include_router(metrics_router)

init_database()


def _seed_default_configuration() -> None:
    db = SessionLocal()
    try:
        ensure_default_organization(db)
        ensure_default_security_policies(db)
        ensure_default_tool_policies(db)
    finally:
        db.close()


_seed_default_configuration()


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "shadow-agent-gateway",
        "proxy_mode": "upstream" if _upstream_proxy_enabled() else "simulated",
        "shared_state": shared_state_backend(),
    }
