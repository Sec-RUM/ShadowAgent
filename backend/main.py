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
from env_loader import load_local_env
from models import (
    AlertEvent,
    ApprovalRequest,
    AuditLog,
    ConsoleUser,
    InterceptLog,
    ReplayRun,
    SecurityPolicy,
    ToolPolicy,
)
from security_controls import (
    Principal,
    create_jwt,
    hash_password,
    rate_limit_middleware,
    redact_text,
    require_admin,
    require_client,
    sanitize_json,
    sanitize_request_id,
    verify_password,
)
from security_engine import (
    AuditDecision,
    behavior_risk_check,
    ensure_default_security_policies,
    ensure_default_tool_policies,
    inspect_prompt,
    permission_control,
    semantic_intent_check,
    separate_instruction_and_data,
)

load_local_env()


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
    version="0.2.0",
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


def _seed_default_configuration() -> None:
    db = SessionLocal()
    try:
        ensure_default_security_policies(db)
        ensure_default_tool_policies(db)
    finally:
        db.close()


_seed_default_configuration()


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


class AnalyzeRequest(BaseModel):
    prompt: str = Field(default="", max_length=12000)
    external_context: str | None = Field(default=None, max_length=20000)
    tool_name: str | None = Field(default=None, max_length=128)
    parameters: dict[str, Any] | None = Field(default=None)


class InterceptLogResponse(BaseModel):
    id: int
    timestamp: str
    threat_type: str
    action_taken: str
    original_prompt: str
    details: dict[str, Any]


class SecurityPolicyResponse(BaseModel):
    id: int
    name: str
    blacklist_keyword: str
    description: str
    severity: str
    scope: str
    enabled: bool
    system_managed: bool


class SecurityPolicyUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    blacklist_keyword: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=4000)
    severity: str = Field(default="medium", max_length=32)
    scope: str = Field(default="Prompt", max_length=64)
    enabled: bool = True


class ToolPolicyResponse(BaseModel):
    id: int
    tool_name: str
    description: str
    allowed: bool
    requires_admin_approval: bool
    system_managed: bool


class ToolPolicyUpsert(BaseModel):
    tool_name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4000)
    allowed: bool = False
    requires_admin_approval: bool = False


class ApprovalRequestResponse(BaseModel):
    id: int
    request_id: str
    status: str
    threat_type: str
    reason: str
    recommended_action: str
    original_prompt: str
    tool_name: str
    categories: list[str]
    evidence: list[str]
    details: dict[str, Any]
    reviewed_by: str
    review_comment: str
    created_at: str
    updated_at: str


class ApprovalReviewRequest(BaseModel):
    status: Literal["approved", "rejected"]
    review_comment: str = Field(default="", max_length=4000)


class AlertEventResponse(BaseModel):
    id: int
    request_id: str
    severity: str
    channel: str
    title: str
    summary: str
    status: str
    details: dict[str, Any]
    created_at: str


class ReplayRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=96)


class ReplayRunResponse(BaseModel):
    id: int
    source_request_id: str
    replay_request_id: str
    triggered_by: str
    verdict: str
    risk_score: str
    category: str
    details: dict[str, Any]
    created_at: str


class AuthRegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=6, max_length=256)


class AuthLoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class AuthUserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: str


class AuthSessionResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: int
    user: AuthUserResponse


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


def _threat_label_from_decision(decision: AuditDecision, layer: str) -> str:
    if decision.category == "tool_permission":
        return "Unauthorized Tool Use"
    if decision.category == "secret_exfiltration":
        return "Data Exfiltration"
    if decision.category == "sensitive_file_access":
        return "Sensitive File Access"
    if decision.category == "internal_network_access":
        return "Internal Network Access"
    if decision.category == "credential_access":
        return "Credential Access"
    if decision.category == "command_execution":
        return "Dangerous Command Execution"
    if decision.category == "destructive_action":
        return "Destructive Command"
    if decision.category == "privilege_escalation":
        return "Privilege Escalation"
    if decision.category == "security_evasion":
        return "Security Evasion"
    if decision.category == "persistence":
        return "Persistence"
    if layer == "tool_permission":
        return "Unauthorized Tool Use"
    return "Prompt Injection"


def _normalized_email(value: str) -> str:
    return value.strip().lower()


def _serialize_console_user(user: ConsoleUser) -> dict[str, Any]:
    return AuthUserResponse(
        id=str(user.id),
        name=user.name,
        email=user.email,
        role=user.role,
        created_at=user.created_at.isoformat(),
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
            created_at=user.created_at.isoformat(),
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
        "category": decision.category,
        "categories": decision.categories,
        "evidence": decision.evidence,
        "recommended_action": decision.recommended_action,
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
    _create_approval_request(
        request_id=request_id,
        decision=decision,
        threat_type=threat_type,
        original_prompt=original_prompt,
        tool_name=(details or {}).get("tool_name"),
        details=log_details,
        db=db,
    )
    _create_alert_event(
        request_id=request_id,
        decision=decision,
        threat_type=threat_type,
        details=log_details,
        db=db,
    )
    db.commit()

    logger.warning(
        "ShadowAgent intercepted request_id=%s layer=%s reason=%s category=%s risk_score=%.2f matched_rules=%s source_excerpt=%r",
        request_id,
        layer,
        decision.reason,
        decision.category,
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
            "category": decision.category,
            "categories": decision.categories,
            "evidence": decision.evidence,
            "recommended_action": decision.recommended_action,
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


def _decision_payload(decision: AuditDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "matched_rules": decision.matched_rules,
        "category": decision.category,
        "categories": decision.categories,
        "evidence": decision.evidence,
        "recommended_action": decision.recommended_action,
    }


def _serialize_policy(policy: SecurityPolicy) -> dict[str, Any]:
    return SecurityPolicyResponse(
        id=policy.id,
        name=policy.name,
        blacklist_keyword=policy.blacklist_keyword,
        description=policy.description,
        severity=policy.severity,
        scope=policy.scope,
        enabled=policy.enabled,
        system_managed=policy.system_managed,
    ).model_dump()


def _serialize_tool_policy(policy: ToolPolicy) -> dict[str, Any]:
    return ToolPolicyResponse(
        id=policy.id,
        tool_name=policy.tool_name,
        description=policy.description,
        allowed=policy.allowed,
        requires_admin_approval=policy.requires_admin_approval,
        system_managed=policy.system_managed,
    ).model_dump()


def _json_loads_safe(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _serialize_approval_request(item: ApprovalRequest) -> dict[str, Any]:
    return ApprovalRequestResponse(
        id=item.id,
        request_id=item.request_id,
        status=item.status,
        threat_type=item.threat_type,
        reason=item.reason,
        recommended_action=item.recommended_action,
        original_prompt=item.original_prompt,
        tool_name=item.tool_name,
        categories=_json_loads_safe(item.categories, []),
        evidence=_json_loads_safe(item.evidence, []),
        details=_json_loads_safe(item.details, {}),
        reviewed_by=item.reviewed_by,
        review_comment=item.review_comment,
        created_at=item.created_at.isoformat(),
        updated_at=item.updated_at.isoformat(),
    ).model_dump()


def _serialize_alert_event(item: AlertEvent) -> dict[str, Any]:
    return AlertEventResponse(
        id=item.id,
        request_id=item.request_id,
        severity=item.severity,
        channel=item.channel,
        title=item.title,
        summary=item.summary,
        status=item.status,
        details=_json_loads_safe(item.details, {}),
        created_at=item.created_at.isoformat(),
    ).model_dump()


def _serialize_replay_run(item: ReplayRun) -> dict[str, Any]:
    return ReplayRunResponse(
        id=item.id,
        source_request_id=item.source_request_id,
        replay_request_id=item.replay_request_id,
        triggered_by=item.triggered_by,
        verdict=item.verdict,
        risk_score=item.risk_score,
        category=item.category,
        details=_json_loads_safe(item.details, {}),
        created_at=item.created_at.isoformat(),
    ).model_dump()


def _should_create_approval(decision: AuditDecision) -> bool:
    high_risk_categories = {
        "tool_permission",
        "command_execution",
        "destructive_action",
        "privilege_escalation",
        "security_evasion",
        "persistence",
        "secret_exfiltration",
        "credential_access",
        "internal_network_access",
        "sensitive_file_access",
    }
    return (
        not decision.allowed
        and (
            decision.risk_score >= 0.85
            or decision.category in high_risk_categories
            or any(category in high_risk_categories for category in decision.categories)
        )
    )


def _create_approval_request(
    *,
    request_id: str,
    decision: AuditDecision,
    threat_type: str,
    original_prompt: str,
    tool_name: str | None,
    details: dict[str, Any],
    db: Session,
) -> None:
    if not _should_create_approval(decision):
        return

    existing = (
        db.query(ApprovalRequest)
        .filter(ApprovalRequest.request_id == request_id, ApprovalRequest.status == "pending")
        .one_or_none()
    )
    if existing is not None:
        return

    db.add(
        ApprovalRequest(
            request_id=request_id,
            status="pending",
            threat_type=threat_type,
            reason=decision.reason,
            recommended_action=decision.recommended_action,
            original_prompt=redact_text(original_prompt),
            tool_name=(tool_name or "").strip(),
            categories=json.dumps(decision.categories, ensure_ascii=False),
            evidence=json.dumps(decision.evidence, ensure_ascii=False),
            details=json.dumps(sanitize_json(details), ensure_ascii=False),
        )
    )


def _create_alert_event(
    *,
    request_id: str,
    decision: AuditDecision,
    threat_type: str,
    details: dict[str, Any],
    db: Session,
) -> None:
    severity = _risk_level(decision.risk_score)
    if severity == "low":
        return

    db.add(
        AlertEvent(
            request_id=request_id,
            severity=severity,
            channel="console",
            title=f"{threat_type} intercepted",
            summary=decision.reason,
            status="triggered",
            details=json.dumps(
                sanitize_json(
                    {
                        "category": decision.category,
                        "categories": decision.categories,
                        "risk_score": decision.risk_score,
                        "matched_rules": decision.matched_rules,
                        **details,
                    }
                ),
                ensure_ascii=False,
            ),
        )
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "shadow-agent-gateway"}


@app.post("/api/v1/auth/register")
async def register_console_user(
    payload: AuthRegisterRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    email = _normalized_email(payload.email)
    existing = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={"error": "email_already_registered", "message": "This email is already registered."},
        )

    role = "admin"
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


@app.post("/api/v1/auth/login")
async def login_console_user(
    payload: AuthLoginRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    email = _normalized_email(payload.email)
    user = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "Invalid email or password."},
        )

    return _auth_session_payload(user)


@app.get("/api/v1/auth/me")
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


@app.get("/api/v1/approvals")
async def list_approval_requests(
    status: str | None = None,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = db.query(ApprovalRequest).order_by(
        ApprovalRequest.created_at.desc(),
        ApprovalRequest.id.desc(),
    )
    if status:
        query = query.filter(ApprovalRequest.status == status)
    return {"items": [_serialize_approval_request(item) for item in query.limit(100).all()]}


@app.post("/api/v1/approvals/{approval_id}/review")
async def review_approval_request(
    approval_id: int,
    payload: ApprovalReviewRequest,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).one_or_none()
    if item is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "approval_not_found", "message": "Approval request does not exist."},
        )

    item.status = payload.status
    item.reviewed_by = _principal_label(principal, db)
    item.review_comment = payload.review_comment.strip()
    db.commit()
    db.refresh(item)
    return {"item": _serialize_approval_request(item)}


@app.get("/api/v1/alerts")
async def list_alert_events(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    items = (
        db.query(AlertEvent)
        .order_by(AlertEvent.created_at.desc(), AlertEvent.id.desc())
        .limit(100)
        .all()
    )
    return {"items": [_serialize_alert_event(item) for item in items]}


def _build_replay_details(log: InterceptLog) -> dict[str, Any]:
    details = _json_loads_safe(log.details, {})
    tool_name = details.get("tool_name") if isinstance(details, dict) else None
    parameters = details.get("parameters") if isinstance(details, dict) else None
    external_context = details.get("external_context") if isinstance(details, dict) else None
    behavior_decision = behavior_risk_check(
        prompt=log.original_prompt,
        external_context=external_context if isinstance(external_context, str) else None,
        tool_name=tool_name if isinstance(tool_name, str) else None,
        parameters=parameters if isinstance(parameters, dict) else None,
    )
    return {
        "request_id": details.get("request_id"),
        "original_threat_type": log.threat_type,
        "original_action": log.action_taken,
        "replayed_behavior_risk": _decision_payload(behavior_decision),
        "source_details": sanitize_json(details),
    }


@app.post("/api/v1/replays")
async def replay_request_by_request_id(
    payload: ReplayRequest,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    logs = (
        db.query(InterceptLog)
        .order_by(InterceptLog.timestamp.desc(), InterceptLog.id.desc())
        .all()
    )
    matched_log: InterceptLog | None = None
    for log in logs:
        details = _json_loads_safe(log.details, {})
        if details.get("request_id") == payload.request_id:
            matched_log = log
            break

    if matched_log is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "replay_source_not_found",
                "message": "No intercepted request matched that request_id.",
            },
        )

    replay_request_id = f"replay-{uuid.uuid4()}"
    replay_details = _build_replay_details(matched_log)
    replay_behavior = replay_details["replayed_behavior_risk"]
    run = ReplayRun(
        source_request_id=payload.request_id,
        replay_request_id=replay_request_id,
        triggered_by=_principal_label(principal, db),
        verdict="blocked" if not bool(replay_behavior["allowed"]) else "allowed",
        risk_score=str(replay_behavior["risk_score"]),
        category=str(replay_behavior["category"]),
        details=json.dumps(sanitize_json(replay_details), ensure_ascii=False),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return {"item": _serialize_replay_run(run)}


@app.get("/api/v1/replays")
async def list_replay_runs(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    items = (
        db.query(ReplayRun)
        .order_by(ReplayRun.created_at.desc(), ReplayRun.id.desc())
        .limit(100)
        .all()
    )
    return {"items": [_serialize_replay_run(item) for item in items]}


@app.get("/api/v1/policies")
async def list_policies(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_security_policies(db)
    policies = (
        db.query(SecurityPolicy)
        .order_by(SecurityPolicy.id.asc())
        .all()
    )
    return {
        "items": [
            _serialize_policy(policy)
            for policy in policies
        ]
    }


@app.post("/api/v1/policies")
async def create_policy(
    payload: SecurityPolicyUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_security_policies(db)
    existing = (
        db.query(SecurityPolicy)
        .filter(SecurityPolicy.name == payload.name.strip())
        .one_or_none()
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "policy_conflict",
                "message": f"Policy {payload.name!r} already exists.",
            },
        )

    policy = SecurityPolicy(
        name=payload.name.strip(),
        blacklist_keyword=payload.blacklist_keyword.strip(),
        description=payload.description.strip(),
        severity=payload.severity.strip().lower() or "medium",
        scope=payload.scope.strip() or "Prompt",
        enabled=payload.enabled,
        system_managed=False,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_policy(policy)}


@app.put("/api/v1/policies/{policy_id}")
async def update_policy(
    policy_id: int,
    payload: SecurityPolicyUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_security_policies(db)
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "policy_not_found", "message": "Policy does not exist."},
        )

    duplicate = (
        db.query(SecurityPolicy)
        .filter(SecurityPolicy.name == payload.name.strip(), SecurityPolicy.id != policy_id)
        .one_or_none()
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "policy_conflict",
                "message": f"Policy {payload.name!r} already exists.",
            },
        )

    policy.name = payload.name.strip()
    policy.blacklist_keyword = payload.blacklist_keyword.strip()
    policy.description = payload.description.strip()
    policy.severity = payload.severity.strip().lower() or "medium"
    policy.scope = payload.scope.strip() or "Prompt"
    policy.enabled = payload.enabled
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_policy(policy)}


@app.delete("/api/v1/policies/{policy_id}")
async def delete_policy(
    policy_id: int,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "policy_not_found", "message": "Policy does not exist."},
        )
    if policy.system_managed:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "policy_delete_blocked",
                "message": "System-managed policies cannot be deleted. Disable or reset them instead.",
            },
        )

    db.delete(policy)
    db.commit()
    return {"deleted": True, "id": policy_id}


@app.post("/api/v1/policies/reset")
async def reset_policies(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    custom_policies = db.query(SecurityPolicy).filter(SecurityPolicy.system_managed.is_(False)).all()
    for policy in custom_policies:
        db.delete(policy)
    db.commit()
    ensure_default_security_policies(db)
    policies = db.query(SecurityPolicy).order_by(SecurityPolicy.id.asc()).all()
    return {"items": [_serialize_policy(policy) for policy in policies]}


@app.get("/api/v1/tool-policies")
async def list_tool_policies(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_tool_policies(db)
    policies = (
        db.query(ToolPolicy)
        .order_by(ToolPolicy.id.asc())
        .all()
    )
    return {
        "items": [
            _serialize_tool_policy(policy)
            for policy in policies
        ]
    }


@app.post("/api/v1/tool-policies")
async def create_tool_policy(
    payload: ToolPolicyUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_tool_policies(db)
    normalized_name = payload.tool_name.strip().lower()
    existing = (
        db.query(ToolPolicy)
        .filter(ToolPolicy.tool_name == normalized_name)
        .one_or_none()
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "tool_policy_conflict",
                "message": f"Tool policy {normalized_name!r} already exists.",
            },
        )

    policy = ToolPolicy(
        tool_name=normalized_name,
        description=payload.description.strip(),
        allowed=payload.allowed,
        requires_admin_approval=payload.requires_admin_approval,
        system_managed=False,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_tool_policy(policy)}


@app.put("/api/v1/tool-policies/{policy_id}")
async def update_tool_policy(
    policy_id: int,
    payload: ToolPolicyUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_tool_policies(db)
    policy = db.query(ToolPolicy).filter(ToolPolicy.id == policy_id).one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "tool_policy_not_found",
                "message": "Tool policy does not exist.",
            },
        )

    normalized_name = payload.tool_name.strip().lower()
    duplicate = (
        db.query(ToolPolicy)
        .filter(ToolPolicy.tool_name == normalized_name, ToolPolicy.id != policy_id)
        .one_or_none()
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "tool_policy_conflict",
                "message": f"Tool policy {normalized_name!r} already exists.",
            },
        )

    policy.tool_name = normalized_name
    policy.description = payload.description.strip()
    policy.allowed = payload.allowed
    policy.requires_admin_approval = payload.requires_admin_approval
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_tool_policy(policy)}


@app.delete("/api/v1/tool-policies/{policy_id}")
async def delete_tool_policy(
    policy_id: int,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    policy = db.query(ToolPolicy).filter(ToolPolicy.id == policy_id).one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "tool_policy_not_found",
                "message": "Tool policy does not exist.",
            },
        )
    if policy.system_managed:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "tool_policy_delete_blocked",
                "message": "System-managed tool policies cannot be deleted. Update or reset them instead.",
            },
        )

    db.delete(policy)
    db.commit()
    return {"deleted": True, "id": policy_id}


@app.post("/api/v1/tool-policies/reset")
async def reset_tool_policies(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    custom_policies = db.query(ToolPolicy).filter(ToolPolicy.system_managed.is_(False)).all()
    for policy in custom_policies:
        db.delete(policy)
    db.commit()
    ensure_default_tool_policies(db)
    policies = db.query(ToolPolicy).order_by(ToolPolicy.id.asc()).all()
    return {"items": [_serialize_tool_policy(policy) for policy in policies]}


@app.post("/api/v1/analyze")
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
        prompt=prompt,
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
