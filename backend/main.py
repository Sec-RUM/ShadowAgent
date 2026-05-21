"""Shadow Agent FastAPI gateway prototype."""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import SessionLocal, get_db, init_database
from models import AuditLog, InterceptLog
from security_controls import (
    Principal,
    rate_limit_middleware,
    redact_text,
    require_admin,
    require_client,
    sanitize_json,
    sanitize_request_id,
)
from security_engine import (
    AuditDecision,
    inspect_prompt,
    permission_control,
    semantic_intent_check,
    separate_instruction_and_data,
)


logger = logging.getLogger("shadow_agent.gateway")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
audit_log_executor = ThreadPoolExecutor(max_workers=2)


def _allowed_origins() -> list[str]:
    configured = os.getenv("SHADOW_AGENT_ALLOWED_ORIGINS")
    if not configured:
        return [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


app = FastAPI(
    title="Shadow Agent Gateway",
    description="Middleware sandbox prototype for LLM agent runtime security.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(rate_limit_middleware)

init_database()


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(min_length=1, max_length=12000)


class ChatCompletionRequest(BaseModel):
    model: str = Field(default="shadow-agent-simulated", max_length=120)
    messages: list[ChatMessage] = Field(min_length=1, max_length=100)
    external_context: str | None = Field(
        default=None,
        max_length=20000,
        description="Untrusted retrieval/API/plugin result to be purified before LLM use.",
    )
    tool_name: str | None = Field(
        default=None,
        max_length=128,
        description="Optional downstream tool name requested by the agent runtime.",
    )
    parameters: dict[str, Any] | None = Field(
        default=None,
        description="Optional downstream tool parameters for permission checks.",
    )
    stream: bool = False


class InterceptLogResponse(BaseModel):
    id: int
    timestamp: str
    threat_type: str
    action_taken: str
    original_prompt: str
    details: dict[str, Any]


def _latest_user_prompt(messages: list[ChatMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.content
    raise HTTPException(
        status_code=400,
        detail={
            "error": "missing_user_message",
            "message": "At least one user message is required.",
        },
    )


def _raise_if_blocked(
    request_id: str,
    layer: str,
    decision: AuditDecision,
    source_excerpt: str,
    original_prompt: str,
    threat_type: str,
    db: Session,
    details: dict[str, Any] | None = None,
) -> None:
    if decision.allowed:
        return

    log_details = {
        "request_id": request_id,
        "layer": layer,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "matched_rules": decision.matched_rules,
        "source_excerpt": redact_text(source_excerpt, max_chars=500),
        **(details or {}),
    }
    db.add(
        InterceptLog(
            threat_type=threat_type,
            action_taken="Blocked",
            original_prompt=redact_text(original_prompt),
            details=json.dumps(sanitize_json(log_details), ensure_ascii=False),
        )
    )
    db.commit()

    logger.warning(
        "ShadowAgent intercepted request_id=%s layer=%s reason=%s risk_score=%.2f matched_rules=%s source_excerpt=%r",
        request_id,
        layer,
        decision.reason,
        decision.risk_score,
        decision.matched_rules,
        source_excerpt[:200],
    )
    raise HTTPException(
        status_code=403,
        detail={
            "error": "shadow_agent_intercepted",
            "request_id": request_id,
            "layer": layer,
            "reason": decision.reason,
            "risk_score": decision.risk_score,
            "matched_rules": decision.matched_rules,
        },
    )


def _risk_level(score: float) -> str:
    if score >= 0.9:
        return "high"
    if score >= 0.75:
        return "medium"
    return "low"


def _persist_audit_log(
    request_id: str,
    original_instruction: str,
    decision: AuditDecision,
    reason: str,
) -> None:
    db = SessionLocal()
    try:
        db.add(
            AuditLog(
                request_id=request_id,
                original_instruction=redact_text(original_instruction),
                risk_level=_risk_level(decision.risk_score),
                triggered_rule_name=", ".join(decision.matched_rules) or "none",
                intercept_reason=reason,
            )
        )
        db.commit()
    finally:
        db.close()


def _submit_audit_log(
    request_id: str,
    layer: str,
    source_text: str,
    decision: AuditDecision,
) -> None:
    if decision.allowed:
        return

    reason = (
        "indirect_prompt_injection_detected_in_untrusted_external_context"
        if layer == "untrusted_external_data"
        else decision.reason
    )
    audit_log_executor.submit(
        _persist_audit_log,
        request_id,
        source_text,
        decision,
        reason,
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "shadow-agent-gateway"}


@app.get("/api/v1/logs")
async def list_intercept_logs(
    limit: int = 20,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 100))
    logs = (
        db.query(InterceptLog)
        .order_by(InterceptLog.timestamp.desc(), InterceptLog.id.desc())
        .limit(safe_limit)
        .all()
    )

    return {
        "items": [
            InterceptLogResponse(
                id=log.id,
                timestamp=log.timestamp.isoformat(),
                threat_type=log.threat_type,
                action_taken=log.action_taken,
                original_prompt=log.original_prompt,
                details=json.loads(log.details),
            ).model_dump()
            for log in logs
        ]
    }


@app.post("/api/v1/chat/completions")
async def chat_completions(
    payload: ChatCompletionRequest,
    request: Request,
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    request_id = (
        sanitize_request_id(request.headers.get("x-request-id")) or str(uuid.uuid4())
    )
    started_at = time.perf_counter()
    prompt = _latest_user_prompt(payload.messages)

    separated = separate_instruction_and_data(prompt, payload.external_context)

    prompt_audit_decision = inspect_prompt(separated["trusted_instruction"], db)
    _submit_audit_log(
        request_id=request_id,
        layer="trusted_instruction",
        source_text=separated["trusted_instruction"],
        decision=prompt_audit_decision,
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="trusted_instruction",
        decision=prompt_audit_decision,
        source_excerpt=separated["trusted_instruction"],
        original_prompt=prompt,
        threat_type="Prompt Injection",
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "audit_source": "database_blacklist_policy",
        },
    )

    external_audit_decision = inspect_prompt(separated["untrusted_data"], db)
    _submit_audit_log(
        request_id=request_id,
        layer="untrusted_external_data",
        source_text=separated["untrusted_data"],
        decision=external_audit_decision,
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="untrusted_external_data",
        decision=external_audit_decision,
        source_excerpt=separated["untrusted_data"],
        original_prompt=prompt,
        threat_type="Prompt Injection",
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "audit_source": "database_blacklist_policy",
            "indirect_prompt_injection": True,
        },
    )

    prompt_decision = semantic_intent_check(separated["trusted_instruction"])
    _raise_if_blocked(
        request_id=request_id,
        layer="trusted_instruction",
        decision=prompt_decision,
        source_excerpt=separated["trusted_instruction"],
        original_prompt=prompt,
        threat_type="Prompt Injection",
        db=db,
        details={"model": payload.model, "principal": principal.subject},
    )

    external_decision = semantic_intent_check(separated["untrusted_data"])
    _raise_if_blocked(
        request_id=request_id,
        layer="untrusted_external_data",
        decision=external_decision,
        source_excerpt=separated["untrusted_data"],
        original_prompt=prompt,
        threat_type="Prompt Injection",
        db=db,
        details={"model": payload.model, "principal": principal.subject},
    )

    permission_decision = permission_control(payload.tool_name, payload.parameters)
    _raise_if_blocked(
        request_id=request_id,
        layer="tool_permission",
        decision=permission_decision,
        source_excerpt=payload.tool_name or "",
        original_prompt=prompt,
        threat_type="Unauthorized API",
        db=db,
        details={
            "model": payload.model,
            "tool_name": payload.tool_name,
            "parameters": sanitize_json(payload.parameters or {}),
            "principal": principal.subject,
        },
    )

    latency_ms = round((time.perf_counter() - started_at) * 1000, 3)
    logger.info(
        "ShadowAgent allowed request_id=%s latency_ms=%.3f model=%s",
        request_id,
        latency_ms,
        payload.model,
    )

    return {
        "id": f"chatcmpl-shadow-{request_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.model,
        "shadow_agent": {
            "request_id": request_id,
            "decision": "allowed",
            "latency_ms": latency_ms,
            "checks": {
                "instruction_data_separation": "applied",
                "semantic_intent": "allowed",
                "permission_control": "allowed",
            },
        },
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Shadow Agent gateway allowed this request. Downstream LLM call is simulated in Task 1.",
                },
                "finish_reason": "stop",
            }
        ],
    }
