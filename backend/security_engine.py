"""Core purification engine for Shadow Agent."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from models import SecurityPolicy


CONTEXT_TAG_PATTERN = re.compile(
    r"<(?P<tag>context|external_context|retrieved_context|tool_result|data)\b[^>]*>"
    r"(?P<body>.*?)"
    r"</(?P=tag)>",
    re.IGNORECASE | re.DOTALL,
)

INJECTION_SIGNATURES = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "system prompt",
    "bypass",
    "you are now",
    "developer mode",
    "jailbreak",
    "reveal hidden instructions",
    "泄露系统提示词",
    "忽略之前的指令",
    "忽略以上指令",
]

INJECTION_PATTERNS = [
    re.compile(re.escape(signature), re.IGNORECASE)
    for signature in INJECTION_SIGNATURES
] + [
    re.compile(r"\bignore (all )?(previous|prior|above) instructions\b", re.IGNORECASE),
    re.compile(r"\bdisregard (all )?(previous|prior|above) instructions\b", re.IGNORECASE),
    re.compile(r"忽略(以上|前述|之前|所有).{0,12}(指令|规则|要求)", re.IGNORECASE),
]

ALLOWED_TOOLS = {
    "search_web": True,
    "read_file": False,
    "execute_shell": False,
}

DEFAULT_SECURITY_POLICIES = [
    {
        "name": "ignore_previous_instructions",
        "blacklist_keyword": r"\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+instructions\b",
        "description": "Blocks attempts to override trusted system or user instructions.",
    },
    {
        "name": "system_prompt_exfiltration",
        "blacklist_keyword": r"\b(system\s+prompt|hidden\s+instructions?|developer\s+message)\b",
        "description": "Blocks attempts to reveal hidden prompts or higher-priority messages.",
    },
    {
        "name": "jailbreak_mode_switch",
        "blacklist_keyword": r"\b(you\s+are\s+now|developer\s+mode|jailbreak|bypass)\b",
        "description": "Blocks jailbreak-style attempts to change the model's operating mode.",
    },
    {
        "name": "tool_result_instruction_smuggling",
        "blacklist_keyword": r"\b(call|execute|run)\s+[^.\n]{0,80}\b(admin|credential|shell|token|secret)\b",
        "description": "Blocks tool-result text that tries to smuggle privileged tool calls.",
    },
    {
        "name": "chinese_instruction_override",
        "blacklist_keyword": r"(忽略|无视|覆盖).{0,16}(之前|以上|系统|开发者).{0,16}(指令|规则|提示)",
        "description": "Blocks Chinese prompt-injection phrasing that overrides prior rules.",
    },
]


@dataclass(slots=True)
class AuditDecision:
    allowed: bool
    reason: str = "allowed"
    risk_score: float = 0.0
    matched_rules: list[str] = field(default_factory=list)


def ensure_default_security_policies(db: Session) -> None:
    """Seed built-in blacklist policies without overwriting local admin changes."""

    existing_names = {
        name
        for (name,) in db.query(SecurityPolicy.name)
        .filter(SecurityPolicy.name.in_([item["name"] for item in DEFAULT_SECURITY_POLICIES]))
        .all()
    }
    missing_policies = [
        SecurityPolicy(**policy)
        for policy in DEFAULT_SECURITY_POLICIES
        if policy["name"] not in existing_names
    ]
    if not missing_policies:
        return

    db.add_all(missing_policies)
    db.commit()


def inspect_prompt(text: str, db: Session) -> AuditDecision:
    """Inspect untrusted prompt text with DB-backed blacklist regex policies.

    This supports indirect prompt-injection defense: callers should inspect
    external retrieval/tool/plugin content separately from trusted user intent.
    """

    if not text.strip():
        return AuditDecision(allowed=True, risk_score=0.0)

    ensure_default_security_policies(db)
    policies = (
        db.query(SecurityPolicy)
        .filter(SecurityPolicy.enabled.is_(True))
        .order_by(SecurityPolicy.id.asc())
        .all()
    )

    matched_rules: list[str] = []
    for policy in policies:
        try:
            pattern = re.compile(policy.blacklist_keyword, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue

        if pattern.search(text):
            matched_rules.append(policy.name)

    if matched_rules:
        return AuditDecision(
            allowed=False,
            reason="blacklisted_prompt_pattern_detected",
            risk_score=0.93,
            matched_rules=matched_rules,
        )

    return AuditDecision(allowed=True, risk_score=0.05)


def separate_instruction_and_data(prompt: str, external_context: str | None) -> dict[str, str]:
    """Separate trusted user intent from tagged untrusted context blocks."""

    extracted_contexts: list[str] = []

    def collect_context(match: re.Match[str]) -> str:
        extracted_contexts.append(match.group("body").strip())
        return " "

    trusted_instruction = CONTEXT_TAG_PATTERN.sub(collect_context, prompt).strip()
    raw_external_context = (external_context or "").strip()
    sanitized_external_context = CONTEXT_TAG_PATTERN.sub(
        collect_context,
        raw_external_context,
    ).strip()
    if sanitized_external_context:
        extracted_contexts.append(sanitized_external_context)

    untrusted_data = "\n\n".join(item for item in extracted_contexts if item)
    return {
        "trusted_instruction": trusted_instruction,
        "untrusted_data": untrusted_data,
    }


def semantic_intent_check(text: str) -> AuditDecision:
    """Detect prompt-injection intent with lightweight signatures."""

    if not text:
        return AuditDecision(allowed=True)

    matched_rules = [
        pattern.pattern for pattern in INJECTION_PATTERNS if pattern.search(text)
    ]
    if matched_rules:
        return AuditDecision(
            allowed=False,
            reason="prompt_injection_detected",
            risk_score=0.92,
            matched_rules=matched_rules,
        )

    return AuditDecision(allowed=True, risk_score=0.05)


def permission_control(tool_name: str | None, parameters: dict[str, Any] | None) -> AuditDecision:
    """Validate whether a tool call is permitted by the simulated sandbox."""

    if not tool_name:
        return AuditDecision(allowed=True)

    normalized_tool_name = tool_name.strip().lower()
    if ALLOWED_TOOLS.get(normalized_tool_name) is not True:
        return AuditDecision(
            allowed=False,
            reason="tool_not_permitted",
            risk_score=0.87,
            matched_rules=[normalized_tool_name],
        )

    if parameters and parameters.get("requires_admin") is True:
        return AuditDecision(
            allowed=False,
            reason="admin_permission_required",
            risk_score=0.75,
            matched_rules=["requires_admin"],
        )

    return AuditDecision(allowed=True, risk_score=0.1)
