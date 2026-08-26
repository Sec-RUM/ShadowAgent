"""Tool permission policy management."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import _record_admin_action
from app.schemas import ToolPolicyUpsert
from app.serializers import _serialize_tool_policy
from database import get_db
from models import ToolPolicy
from security_controls import Principal, require_admin
from security_engine import ensure_default_tool_policies

router = APIRouter(prefix="/api/v1/tool-policies", tags=["tool-policies"])


@router.get("")
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


@router.post("")
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
    _record_admin_action(
        db,
        action="tool_policy_created",
        target=normalized_name,
        principal=principal,
    )
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_tool_policy(policy)}


@router.put("/{policy_id}")
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
    _record_admin_action(
        db,
        action="tool_policy_updated",
        target=policy.tool_name,
        principal=principal,
    )
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_tool_policy(policy)}


@router.delete("/{policy_id}")
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

    _record_admin_action(
        db,
        action="tool_policy_deleted",
        target=policy.tool_name,
        principal=principal,
    )
    db.delete(policy)
    db.commit()
    return {"deleted": True, "id": policy_id}


@router.post("/reset")
async def reset_tool_policies(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    custom_policies = db.query(ToolPolicy).filter(ToolPolicy.system_managed.is_(False)).all()
    for policy in custom_policies:
        db.delete(policy)
    _record_admin_action(
        db,
        action="tool_policies_reset",
        target="all",
        principal=principal,
        details={"deleted_count": len(custom_policies)},
    )
    db.commit()
    ensure_default_tool_policies(db)
    policies = db.query(ToolPolicy).order_by(ToolPolicy.id.asc()).all()
    return {"items": [_serialize_tool_policy(policy) for policy in policies]}
