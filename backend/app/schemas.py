"""Pydantic request/response schemas for every gateway endpoint."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(min_length=1, max_length=12000)


MAX_SERIALIZED_PARAMETERS_LENGTH = 20_000


def _validate_parameters_size(value: dict[str, Any] | None) -> dict[str, Any] | None:
    """Reject oversized tool parameter payloads before they reach the engines."""
    if value is None:
        return None
    serialized = json.dumps(value, ensure_ascii=False, default=str)
    if len(serialized) > MAX_SERIALIZED_PARAMETERS_LENGTH:
        raise ValueError(
            "parameters payload is too large (max 20000 characters when serialized)"
        )
    return value


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

    @field_validator("parameters")
    @classmethod
    def _check_parameters_size(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_parameters_size(value)


class AnalyzeRequest(BaseModel):
    prompt: str = Field(default="", max_length=12000)
    external_context: str | None = Field(default=None, max_length=20000)
    tool_name: str | None = Field(default=None, max_length=128)
    parameters: dict[str, Any] | None = Field(default=None)

    @field_validator("parameters")
    @classmethod
    def _check_parameters_size(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_parameters_size(value)


class InterceptLogResponse(BaseModel):
    id: int
    request_id: str = ""
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


class CustomRuleUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4000)
    rule_type: Literal["regex", "keyword"]
    pattern: str = Field(min_length=1, max_length=512)
    target: Literal["prompt", "response", "any"] = "prompt"
    action: Literal["block", "redact", "alert"] = "block"
    risk_score: float = Field(default=0.8, ge=0.0, le=1.0)
    enabled: bool = True


class CustomRuleTestRequest(BaseModel):
    """Test a rule (existing by id, or an ad-hoc draft) against sample text."""

    sample_text: str = Field(min_length=0, max_length=20000)
    rule_id: int | None = None
    draft: CustomRuleUpsert | None = None


class CustomRuleImportRequest(BaseModel):
    rules: list[CustomRuleUpsert] = Field(min_length=1, max_length=200)
    mode: Literal["merge", "replace"] = "merge"


class CustomRuleResponse(BaseModel):
    id: int
    name: str
    description: str
    rule_type: str
    pattern: str
    target: str
    action: str
    risk_score: float
    enabled: bool
    created_at: str
    updated_at: str


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


class AuthOrgResponse(BaseModel):
    """Active organization context embedded in a console session."""

    id: int
    slug: str
    name: str
    role: str
    is_default: bool = False


class AuthSessionResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: int
    user: AuthUserResponse
    org: AuthOrgResponse | None = None


class SwitchOrgRequest(BaseModel):
    org_id: int


class OrgCreateRequest(BaseModel):
    slug: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,62}[a-zA-Z0-9]$")
    name: str = Field(min_length=1, max_length=128)


class OrgUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class OrgMemberAddRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: Literal["owner", "admin", "member"] = "member"


class OrgMemberUpdateRequest(BaseModel):
    role: Literal["owner", "admin", "member"]


class SsoUpsertRequest(BaseModel):
    """Per-organization OIDC connection (Authorization Code + PKCE)."""

    provider_name: str = Field(min_length=1, max_length=128)
    client_id: str = Field(min_length=1, max_length=255)
    # Empty string keeps the stored secret (update flows never echo it back).
    client_secret: str = Field(default="", max_length=512)
    issuer_url: str = Field(min_length=1, max_length=512)
    scopes: str = Field(default="openid email profile", max_length=255)
    jit_enabled: bool = True
    default_role: str = Field(default="client", min_length=1, max_length=32)
    enabled: bool = True


class ConsoleBootstrapStatusResponse(BaseModel):
    initialized: bool
    bootstrap_required: bool
    bootstrap_token_configured: bool
    demo_override_enabled: bool
    open_registration_enabled: bool
    invite_token_configured: bool
    recommended_role: str


class ManagedApiKeyResponse(BaseModel):
    id: int
    name: str
    role: str
    description: str
    key_prefix: str
    masked_key: str
    created_by: str
    is_active: bool
    expires_at: str | None
    last_used_at: str | None
    last_used_by: str
    created_at: str
    updated_at: str


class ManagedApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: str = Field(default="client", min_length=1, max_length=32)
    description: str = Field(default="", max_length=4000)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class ManagedApiKeyCreateResponse(BaseModel):
    item: ManagedApiKeyResponse
    api_key: str


class ManagedApiKeyRotateRequest(BaseModel):
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    clear_expiration: bool = False
