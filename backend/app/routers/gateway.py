"""Gateway core: /analyze inspection and /chat/completions enforcement."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import (
    _decision_payload,
    _raise_if_blocked,
    _submit_audit_log,
    _threat_label_from_decision,
)
from app.config import _allow_simulated_responses, _upstream_proxy_enabled
from app.schemas import AnalyzeRequest, ChatCompletionRequest, ChatMessage
from app.upstream import (
    _attach_shadow_agent_metadata,
    _forward_to_upstream,
    _resolved_upstream_model,
    _stream_upstream_response,
)
from database import get_db
from security_controls import (
    Principal,
    require_client,
    sanitize_json,
    sanitize_request_id,
)
from security_engine import (
    behavior_risk_check,
    inspect_prompt,
    permission_control,
    semantic_intent_check,
    separate_instruction_and_data,
)

logger = logging.getLogger("shadow_agent.gateway")

router = APIRouter(prefix="/api/v1", tags=["gateway"])


def _conversation_text(messages: list[ChatMessage]) -> str:
    """Build the non-system conversation transcript for history-wide auditing.

    System messages are treated as trusted client-side configuration; user,
    assistant, and tool history can carry smuggled injection payloads that
    last-user-message checks alone would miss.
    """
    return "\n".join(
        f"[{message.role}] {message.content}"
        for message in messages
        if message.role != "system"
    )


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


@router.post("/analyze")
async def analyze_request(
    payload: AnalyzeRequest,
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    separated = separate_instruction_and_data(payload.prompt, payload.external_context)

    checks = {
        "prompt_blacklist": _decision_payload(
            inspect_prompt(separated["trusted_instruction"], db)
        ),
        "external_blacklist": _decision_payload(
            inspect_prompt(separated["untrusted_data"], db)
        ),
        "semantic_prompt": _decision_payload(
            semantic_intent_check(separated["trusted_instruction"])
        ),
        "semantic_external": _decision_payload(
            semantic_intent_check(separated["untrusted_data"])
        ),
        "permission_control": _decision_payload(
            permission_control(payload.tool_name, payload.parameters, db)
        ),
        "behavior_risk": _decision_payload(
            behavior_risk_check(
                payload.prompt,
                payload.external_context,
                payload.tool_name,
                payload.parameters,
            )
        ),
    }

    blocked_checks = [
        {"name": name, **decision}
        for name, decision in checks.items()
        if not bool(decision["allowed"])
    ]
    final_score = max([0.0, *[float(item["risk_score"]) for item in checks.values()]])
    final_category = blocked_checks[0]["category"] if blocked_checks else "none"
    final_recommended_action = (
        blocked_checks[0]["recommended_action"] if blocked_checks else "allow"
    )

    return {
        "decision": "blocked" if blocked_checks else "allowed",
        "risk_score": final_score,
        "category": final_category,
        "recommended_action": final_recommended_action,
        "blocked_checks": blocked_checks,
        "checks": checks,
        "separation": separated,
    }


@router.post("/chat/completions")
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
    conversation_text = _conversation_text(payload.messages)

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
        threat_type=_threat_label_from_decision(prompt_audit_decision, "trusted_instruction"),
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
        threat_type=_threat_label_from_decision(external_audit_decision, "untrusted_external_data"),
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
        threat_type=_threat_label_from_decision(prompt_decision, "trusted_instruction"),
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
        threat_type=_threat_label_from_decision(external_decision, "untrusted_external_data"),
        db=db,
        details={"model": payload.model, "principal": principal.subject},
    )

    conversation_blacklist_decision = inspect_prompt(conversation_text, db)
    _submit_audit_log(
        request_id=request_id,
        layer="conversation_history",
        source_text=conversation_text,
        decision=conversation_blacklist_decision,
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="conversation_history",
        decision=conversation_blacklist_decision,
        source_excerpt=conversation_text,
        original_prompt=prompt,
        threat_type=_threat_label_from_decision(
            conversation_blacklist_decision,
            "conversation_history",
        ),
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "audit_source": "database_blacklist_policy",
            "indirect_prompt_injection": True,
            "conversation_history_audit": True,
        },
    )

    conversation_decision = semantic_intent_check(conversation_text)
    _raise_if_blocked(
        request_id=request_id,
        layer="conversation_history",
        decision=conversation_decision,
        source_excerpt=conversation_text,
        original_prompt=prompt,
        threat_type=_threat_label_from_decision(conversation_decision, "conversation_history"),
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "conversation_history_audit": True,
        },
    )

    permission_decision = permission_control(payload.tool_name, payload.parameters, db)
    _raise_if_blocked(
        request_id=request_id,
        layer="tool_permission",
        decision=permission_decision,
        source_excerpt=payload.tool_name or "",
        original_prompt=prompt,
        threat_type=_threat_label_from_decision(permission_decision, "tool_permission"),
        db=db,
        details={
            "model": payload.model,
            "tool_name": payload.tool_name,
            "parameters": sanitize_json(payload.parameters or {}),
            "principal": principal.subject,
        },
    )

    behavior_decision = behavior_risk_check(
        prompt=conversation_text,
        external_context=payload.external_context,
        tool_name=payload.tool_name,
        parameters=payload.parameters,
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="behavior_risk",
        decision=behavior_decision,
        source_excerpt=json.dumps(sanitize_json(payload.parameters or {}), ensure_ascii=False),
        original_prompt=prompt,
        threat_type=_threat_label_from_decision(behavior_decision, "behavior_risk"),
        db=db,
        details={
            "model": payload.model,
            "tool_name": payload.tool_name,
            "parameters": sanitize_json(payload.parameters or {}),
            "principal": principal.subject,
            "external_context_present": bool((payload.external_context or "").strip()),
        },
    )

    latency_ms = round((time.perf_counter() - started_at) * 1000, 3)
    logger.info(
        "ShadowAgent allowed request_id=%s latency_ms=%.3f model=%s",
        request_id,
        latency_ms,
        payload.model,
    )

    if payload.stream:
        if _upstream_proxy_enabled():
            return await _stream_upstream_response(
                payload,
                request_id=request_id,
                separated=separated,
            )
        if not _allow_simulated_responses():
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "streaming_requires_upstream",
                    "message": "Streaming mode requires a configured upstream LLM provider.",
                },
            )

    if _upstream_proxy_enabled():
        upstream_response = await _forward_to_upstream(
            payload,
            request_id=request_id,
            separated=separated,
        )
        return _attach_shadow_agent_metadata(
            upstream_response,
            request_id=request_id,
            latency_ms=latency_ms,
            upstream_model=_resolved_upstream_model(payload.model),
        )

    if not _allow_simulated_responses():
        raise HTTPException(
            status_code=503,
            detail={
                "error": "upstream_not_configured",
                "message": (
                    "Configure SHADOW_AGENT_UPSTREAM_BASE_URL or "
                    "SHADOW_AGENT_UPSTREAM_CHAT_COMPLETIONS_URL to enable real LLM proxying. "
                    "Set SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=true only for local demos."
                ),
            },
        )

    return {
        "id": f"chatcmpl-shadow-{request_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.model,
        "shadow_agent": {
            "request_id": request_id,
            "decision": "allowed",
            "mode": "simulated",
            "latency_ms": latency_ms,
            "checks": {
                "instruction_data_separation": "applied",
                "semantic_intent": "allowed",
                "permission_control": "allowed",
                "behavior_risk": "allowed",
            },
        },
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Shadow Agent gateway allowed this request. Downstream LLM call is simulated in this prototype.",
                },
                "finish_reason": "stop",
            }
        ],
    }
