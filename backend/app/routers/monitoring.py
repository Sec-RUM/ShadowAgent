"""Console monitoring: intercept logs, approval workflow, alert events, SSE stream."""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.audit import _record_admin_action
from app.auth_helpers import _principal_label
from app.events import subscribe, unsubscribe
from app.schemas import ApprovalReviewRequest, InterceptLogResponse
from app.semantic import semantic_status
from app.serializers import _serialize_alert_event, _serialize_approval_request
from app.utils import _json_loads_safe, _utc_timestamp
from database import get_db
from models import AlertEvent, ApprovalRequest, InterceptLog
from security_controls import Principal, require_admin

router = APIRouter(prefix="/api/v1", tags=["monitoring"])

_SSE_HEARTBEAT_SECONDS = 15.0


@router.get("/semantic-status")
async def get_semantic_status(
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    """Request-side semantic detection runtime status (mode/threshold/model)."""
    return semantic_status()


async def _sse_event_stream() -> AsyncIterator[str]:
    """Yield `text/event-stream` frames: replay history, then live events."""
    queue = subscribe()
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=_SSE_HEARTBEAT_SECONDS)
                payload = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                yield f"event: {event.get('type', 'message')}\ndata: {payload}\n\n"
            except asyncio.TimeoutError:
                yield ": ping\n\n"
    finally:
        unsubscribe(queue)


@router.get("/events/stream")
async def stream_security_events(
    principal: Principal = Depends(require_admin),
) -> StreamingResponse:
    """Server-Sent Events stream of real-time intercepts (admin only).

    Clients should use `fetch()` with header-based auth (EventSource cannot
    send Authorization headers). Frames: `event: intercept` with a JSON
    payload; `: ping` comments every 15s as heartbeat.
    """
    return StreamingResponse(
        _sse_event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable proxy buffering
        },
    )


@router.get("/logs")
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
                request_id=log.request_id or "",
                timestamp=_utc_timestamp(log.timestamp) or "",
                threat_type=log.threat_type,
                action_taken=log.action_taken,
                original_prompt=log.original_prompt,
                details=_json_loads_safe(log.details, {}),
            ).model_dump()
            for log in logs
        ]
    }


@router.get("/approvals")
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


@router.post("/approvals/{approval_id}/review")
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
    if item.status != "pending":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "approval_already_reviewed",
                "message": f"Approval request has already been {item.status}.",
            },
        )

    item.status = payload.status
    item.reviewed_by = _principal_label(principal, db)
    item.review_comment = payload.review_comment.strip()
    _record_admin_action(
        db,
        action="approval_reviewed",
        target=f"approval:{item.request_id}",
        principal=principal,
        details={"status": payload.status},
    )
    db.commit()
    db.refresh(item)
    return {"item": _serialize_approval_request(item)}


@router.get("/alerts")
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
