"""Core purification and behavior-risk engine for Shadow Agent."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from models import SecurityPolicy, ToolPolicy


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
]

INJECTION_PATTERNS = [
    re.compile(re.escape(signature), re.IGNORECASE)
    for signature in INJECTION_SIGNATURES
] + [
    re.compile(
        r"\bignore (all )?(previous|prior|above) instructions\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdisregard (all )?(previous|prior|above) instructions\b",
        re.IGNORECASE,
    ),
]

COMMAND_PARAMETER_KEYS = {
    "command",
    "cmd",
    "script",
    "shell_command",
    "powershell",
    "bash",
}
FILE_PARAMETER_KEYS = {
    "path",
    "file",
    "filename",
    "filepath",
    "target_path",
    "source_path",
}
NETWORK_PARAMETER_KEYS = {
    "url",
    "uri",
    "endpoint",
    "host",
    "hostname",
    "address",
    "target",
    "webhook",
    "callback_url",
}
NETWORK_TOOL_NAMES = {
    "http_request",
    "fetch_url",
    "webhook_post",
    "search_web",
}
SHELL_TOOL_NAMES = {
    "execute_shell",
    "run_shell",
    "powershell",
    "bash",
    "terminal",
}
FILE_TOOL_NAMES = {
    "read_file",
    "write_file",
    "list_files",
}

SECRET_TEXT_PATTERNS = [
    re.compile(r"(?i)\bapi(?:[_\-\s]+)?key\b"),
    re.compile(r"(?i)\baccess(?:[_\-\s]+)?token\b"),
    re.compile(r"(?i)\brefresh(?:[_\-\s]+)?token\b"),
    re.compile(r"(?i)\bsecret\b"),
    re.compile(r"(?i)\bpassword\b"),
    re.compile(r"(?i)\bauthorization\b"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{10,}\b"),
]
EXFIL_ACTION_PATTERN = re.compile(
    r"(?i)\b(send|upload|post|exfiltrat(?:e|ion)|transmit|export|leak|share|dump)\b"
)
EXFIL_DESTINATION_PATTERN = re.compile(
    r"(?i)\b(webhook|pastebin|gist|dropbox|s3|discord|slack|telegram|email|remote server|callback)\b"
)
ACCESS_INTENT_PATTERN = re.compile(
    r"(?i)\b(read|open|load|cat|copy|dump|query|request|fetch|call|visit|connect|upload|send|curl|wget)\b"
)
EXECUTION_INTENT_PATTERN = re.compile(
    r"(?i)\b(run|execute|launch|invoke|start)\b"
)
COMMAND_DESTRUCTIVE_PATTERNS = [
    (
        "destructive_delete_command",
        re.compile(r"(?i)\b(rm\s+-rf|del\s+/f\s+/s\s+/q|Remove-Item\b.+-Recurse)\b"),
        0.98,
        "destructive_action",
        "Destructive delete command detected.",
    ),
    (
        "disk_format_command",
        re.compile(r"(?i)\b(format\s+[a-z]:|mkfs(?:\.[a-z0-9]+)?)\b"),
        0.99,
        "destructive_action",
        "Disk formatting command detected.",
    ),
    (
        "credential_dump_command",
        re.compile(
            r"(?i)\b(reg\s+save\s+HKLM\\SAM|mimikatz|lsass|samdump|secretsdump)\b"
        ),
        0.97,
        "credential_access",
        "Credential dumping command detected.",
    ),
    (
        "encoded_powershell",
        re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\n]{0,80}(?:-enc|-encodedcommand)\b"),
        0.9,
        "command_execution",
        "Obfuscated PowerShell execution detected.",
    ),
    (
        "security_evasion_command",
        re.compile(
            r"(?i)\b(Set-MpPreference|Add-MpPreference|sc\s+(stop|config)\s+WinDefend|Stop-Service\s+\w*Defender|ufw\s+disable|iptables\s+-F|wevtutil\s+cl|Clear-EventLog)\b"
        ),
        0.96,
        "security_evasion",
        "Security control disablement or log tampering detected.",
    ),
    (
        "persistence_command",
        re.compile(
            r"(?i)\b(schtasks\s+/create|crontab\b|systemctl\s+enable\b|reg\s+add\s+HK(?:CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|launchctl\s+load)\b"
        ),
        0.95,
        "persistence",
        "Persistence mechanism creation detected.",
    ),
    (
        "download_execute_command",
        re.compile(
            r"(?i)\b(curl|wget|Invoke-WebRequest|iwr)\b[^\n|]{0,200}\|\s*(bash|sh|powershell|pwsh)\b"
        ),
        0.97,
        "command_execution",
        "Remote script download-and-execute pattern detected.",
    ),
    (
        "reverse_shell_command",
        re.compile(
            r"(?i)(\b(nc|netcat)\b[^\n]{0,80}\s-e\s|\bbash\s+-i\b[^\n]{0,120}/dev/tcp/|\bpowershell(?:\.exe)?\b[^\n]{0,200}\bTcpClient\b)"
        ),
        0.98,
        "command_execution",
        "Reverse shell or interactive callback execution detected.",
    ),
]
SENSITIVE_FILE_PATTERNS = [
    (
        "dotenv_secret_file",
        re.compile(r"(?i)(^|[\\/])\.env(?:\.[a-z0-9_-]+)?$"),
        0.9,
        "sensitive_file_access",
        "Environment secret file access detected.",
    ),
    (
        "ssh_private_key",
        re.compile(r"(?i)(^|[\\/])(\.ssh[\\/].*(id_rsa|id_ed25519)|id_rsa|id_ed25519)$"),
        0.97,
        "sensitive_file_access",
        "SSH private key access detected.",
    ),
    (
        "cloud_credentials",
        re.compile(
            r"(?i)(^|[\\/])(\.aws[\\/]credentials|\.kube[\\/]config|\.docker[\\/]config\.json)$"
        ),
        0.95,
        "sensitive_file_access",
        "Cloud or cluster credentials access detected.",
    ),
    (
        "developer_credentials_file",
        re.compile(r"(?i)(^|[\\/])(\.git-credentials|\.npmrc|\.pypirc)$"),
        0.92,
        "sensitive_file_access",
        "Developer credential file access detected.",
    ),
    (
        "system_password_file",
        re.compile(r"(?i)(/etc/(passwd|shadow)|[\\/]SAM|[\\/]NTDS\.dit)$"),
        0.98,
        "sensitive_file_access",
        "System credential store access detected.",
    ),
]
INTERNAL_TARGET_PATTERNS = [
    (
        "cloud_metadata_service",
        re.compile(
            r"(?i)\b(169\.254\.169\.254|metadata\.google\.internal|metadata\.tencentyun\.com|100\.100\.100\.200)\b"
        ),
        0.98,
        "internal_network_access",
        "Cloud metadata service target detected.",
    ),
    (
        "localhost_target",
        re.compile(r"(?i)\b(localhost|127\.0\.0\.1|::1|0\.0\.0\.0|host\.docker\.internal)\b"),
        0.91,
        "internal_network_access",
        "Loopback or container-local target detected.",
    ),
    (
        "private_rfc1918_target",
        re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"),
        0.88,
        "internal_network_access",
        "Private network target detected.",
    ),
]
PRIVILEGE_ESCALATION_PATTERNS = [
    (
        "admin_flag_requested",
        re.compile(r"(?i)\b(requires_admin|run_as_admin|elevated|administrator|sudo)\b"),
        0.89,
        "privilege_escalation",
        "Elevated execution requested.",
    ),
    (
        "permission_bypass_language",
        re.compile(r"(?i)\b(bypass|disable|ignore)\b.{0,30}\b(permission|approval|policy|guardrail)\b"),
        0.94,
        "privilege_escalation",
        "Guardrail bypass language detected.",
    ),
]

DEFAULT_SECURITY_POLICIES = [
    {
        "name": "ignore_previous_instructions",
        "blacklist_keyword": r"\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+instructions\b",
        "description": "Blocks attempts to override trusted system or user instructions.",
        "severity": "high",
        "scope": "Prompt",
        "system_managed": True,
    },
    {
        "name": "system_prompt_exfiltration",
        "blacklist_keyword": r"\b(system\s+prompt|hidden\s+instructions?|developer\s+message)\b",
        "description": "Blocks attempts to reveal hidden prompts or higher-priority messages.",
        "severity": "high",
        "scope": "Prompt",
        "system_managed": True,
    },
    {
        "name": "jailbreak_mode_switch",
        "blacklist_keyword": r"\b(you\s+are\s+now|developer\s+mode|jailbreak|bypass)\b",
        "description": "Blocks jailbreak-style attempts to change the model's operating mode.",
        "severity": "high",
        "scope": "Prompt",
        "system_managed": True,
    },
    {
        "name": "tool_result_instruction_smuggling",
        "blacklist_keyword": r"\b(call|execute|run)\s+[^.\n]{0,80}\b(admin|credential|shell|token|secret)\b",
        "description": "Blocks tool-result text that tries to smuggle privileged tool calls.",
        "severity": "high",
        "scope": "Tool",
        "system_managed": True,
    },
]

DEFAULT_TOOL_POLICIES = [
    {
        "tool_name": "search_web",
        "description": "Allows open-web search while keeping results untrusted.",
        "allowed": True,
        "requires_admin_approval": False,
        "system_managed": True,
    },
    {
        "tool_name": "http_request",
        "description": "Allows outbound HTTP requests except internal or metadata targets.",
        "allowed": True,
        "requires_admin_approval": False,
        "system_managed": True,
    },
    {
        "tool_name": "read_file",
        "description": "Reads workspace files. Sensitive secrets and credential stores stay blocked.",
        "allowed": True,
        "requires_admin_approval": False,
        "system_managed": True,
    },
    {
        "tool_name": "execute_shell",
        "description": "Executes shell commands. Disabled by default because of high impact.",
        "allowed": False,
        "requires_admin_approval": True,
        "system_managed": True,
    },
]


@dataclass(slots=True)
class AuditDecision:
    allowed: bool
    reason: str = "allowed"
    risk_score: float = 0.0
    matched_rules: list[str] = field(default_factory=list)
    category: str = "none"
    categories: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommended_action: str = "allow"


@dataclass(frozen=True, slots=True)
class ThreatMatch:
    rule_name: str
    category: str
    score: float
    evidence: str
    reason: str


def ensure_default_security_policies(db: Session) -> None:
    """Seed built-in blacklist policies and keep system-managed metadata in sync."""

    default_by_name = {item["name"]: item for item in DEFAULT_SECURITY_POLICIES}
    existing_policies = (
        db.query(SecurityPolicy)
        .filter(SecurityPolicy.name.in_(list(default_by_name)))
        .all()
    )
    existing_by_name = {policy.name: policy for policy in existing_policies}

    changed = False
    for name, default in default_by_name.items():
        existing = existing_by_name.get(name)
        if existing is None:
            db.add(SecurityPolicy(**default))
            changed = True
            continue

        updates = {
            "blacklist_keyword": default["blacklist_keyword"],
            "description": default["description"],
            "severity": default["severity"],
            "scope": default["scope"],
            "system_managed": default["system_managed"],
        }
        for field_name, field_value in updates.items():
            if getattr(existing, field_name) != field_value:
                setattr(existing, field_name, field_value)
                changed = True

    if changed:
        db.commit()


def ensure_default_tool_policies(db: Session) -> None:
    """Seed built-in tool policies and keep system-managed metadata in sync."""

    default_by_name = {item["tool_name"]: item for item in DEFAULT_TOOL_POLICIES}
    existing_policies = (
        db.query(ToolPolicy)
        .filter(ToolPolicy.tool_name.in_(list(default_by_name)))
        .all()
    )
    existing_by_name = {policy.tool_name: policy for policy in existing_policies}

    changed = False
    for tool_name, default in default_by_name.items():
        existing = existing_by_name.get(tool_name)
        if existing is None:
            db.add(ToolPolicy(**default))
            changed = True
            continue

        updates = {
            "description": default["description"],
            "allowed": default["allowed"],
            "requires_admin_approval": default["requires_admin_approval"],
            "system_managed": default["system_managed"],
        }
        for field_name, field_value in updates.items():
            if getattr(existing, field_name) != field_value:
                setattr(existing, field_name, field_value)
                changed = True

    if changed:
        db.commit()


def inspect_prompt(text: str, db: Session) -> AuditDecision:
    """Inspect untrusted prompt text with DB-backed blacklist regex policies."""

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
    evidence: list[str] = []
    for policy in policies:
        try:
            pattern = re.compile(policy.blacklist_keyword, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue

        match = pattern.search(text)
        if match:
            matched_rules.append(policy.name)
            evidence.append(match.group(0)[:200])

    if matched_rules:
        return AuditDecision(
            allowed=False,
            reason="blacklisted_prompt_pattern_detected",
            risk_score=0.93,
            matched_rules=matched_rules,
            category="prompt_injection",
            categories=["prompt_injection"],
            evidence=evidence[:6],
            recommended_action="block",
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

    matched_rules: list[str] = []
    evidence: list[str] = []
    for pattern in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            matched_rules.append(pattern.pattern)
            evidence.append(match.group(0)[:200])

    if matched_rules:
        return AuditDecision(
            allowed=False,
            reason="prompt_injection_detected",
            risk_score=0.92,
            matched_rules=matched_rules,
            category="prompt_injection",
            categories=["prompt_injection"],
            evidence=evidence[:6],
            recommended_action="block",
        )

    return AuditDecision(allowed=True, risk_score=0.05)


def permission_control(
    tool_name: str | None,
    parameters: dict[str, Any] | None,
    db: Session | None = None,
) -> AuditDecision:
    """Validate whether a tool call is permitted by configured tool policy."""

    if not tool_name:
        return AuditDecision(allowed=True)

    normalized_tool_name = tool_name.strip().lower()
    policy: ToolPolicy | None = None

    if db is not None:
        ensure_default_tool_policies(db)
        policy = (
            db.query(ToolPolicy)
            .filter(ToolPolicy.tool_name == normalized_tool_name)
            .one_or_none()
        )

    if policy is None:
        fallback = next(
            (
                item
                for item in DEFAULT_TOOL_POLICIES
                if item["tool_name"] == normalized_tool_name
            ),
            None,
        )
        if fallback is not None:
            allowed = bool(fallback["allowed"])
            requires_admin_approval = bool(fallback["requires_admin_approval"])
        else:
            allowed = False
            requires_admin_approval = False
    else:
        allowed = policy.allowed
        requires_admin_approval = policy.requires_admin_approval

    if not allowed:
        return AuditDecision(
            allowed=False,
            reason="tool_not_permitted",
            risk_score=0.87,
            matched_rules=[normalized_tool_name],
            category="tool_permission",
            categories=["tool_permission"],
            evidence=[f"tool={normalized_tool_name}"],
            recommended_action="block",
        )

    if parameters:
        flattened = _flatten_parameter_entries(parameters)
        if any(
            entry.value_text.lower() == "true"
            and entry.path.lower().endswith("requires_admin")
            for entry in flattened
        ):
            return AuditDecision(
                allowed=False,
                reason="admin_permission_required",
                risk_score=0.83,
                matched_rules=["requires_admin"],
                category="tool_permission",
                categories=["tool_permission", "privilege_escalation"],
                evidence=["requires_admin=true"],
                recommended_action="block",
            )

    if requires_admin_approval:
        return AuditDecision(
            allowed=False,
            reason="admin_approval_required",
            risk_score=0.79,
            matched_rules=[normalized_tool_name],
            category="tool_permission",
            categories=["tool_permission"],
            evidence=[f"tool={normalized_tool_name} requires admin approval"],
            recommended_action="block",
        )

    return AuditDecision(allowed=True, risk_score=0.1)


def behavior_risk_check(
    prompt: str,
    external_context: str | None,
    tool_name: str | None,
    parameters: dict[str, Any] | None,
) -> AuditDecision:
    """Detect concrete high-risk actions across prompt, context, tool, and parameters."""

    normalized_tool_name = (tool_name or "").strip().lower()
    flattened = _flatten_parameter_entries(parameters or {})
    combined_text = "\n".join(
        part for part in [prompt.strip(), (external_context or "").strip()] if part
    )

    matches: list[ThreatMatch] = []
    matches.extend(_match_dangerous_commands(normalized_tool_name, flattened, combined_text))
    matches.extend(_match_sensitive_files(normalized_tool_name, flattened, combined_text))
    matches.extend(_match_internal_targets(normalized_tool_name, flattened, combined_text))
    matches.extend(
        _match_privilege_escalation(
            normalized_tool_name,
            flattened,
            combined_text,
        )
    )
    matches.extend(
        _match_secret_exfiltration(
            normalized_tool_name,
            flattened,
            combined_text,
        )
    )

    if not matches:
        return AuditDecision(allowed=True, risk_score=0.08)

    top_match = max(matches, key=lambda item: item.score)
    return AuditDecision(
        allowed=False,
        reason="dangerous_behavior_detected",
        risk_score=top_match.score,
        matched_rules=[item.rule_name for item in matches],
        category=top_match.category,
        categories=sorted({item.category for item in matches}),
        evidence=[item.evidence for item in matches[:8]],
        recommended_action="block",
    )


@dataclass(frozen=True, slots=True)
class ParameterEntry:
    path: str
    value_text: str


def _flatten_parameter_entries(value: Any, prefix: str = "") -> list[ParameterEntry]:
    entries: list[ParameterEntry] = []

    if isinstance(value, dict):
        for key, item in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            entries.extend(_flatten_parameter_entries(item, next_prefix))
        return entries

    if isinstance(value, list):
        for index, item in enumerate(value):
            next_prefix = f"{prefix}[{index}]"
            entries.extend(_flatten_parameter_entries(item, next_prefix))
        return entries

    if value is None:
        entries.append(ParameterEntry(path=prefix or "value", value_text="null"))
        return entries

    entries.append(ParameterEntry(path=prefix or "value", value_text=str(value)))
    return entries


def _tool_can_execute_commands(tool_name: str) -> bool:
    return tool_name in SHELL_TOOL_NAMES


def _tool_can_access_files(tool_name: str) -> bool:
    return tool_name in FILE_TOOL_NAMES or tool_name in SHELL_TOOL_NAMES


def _tool_can_access_network(tool_name: str) -> bool:
    return tool_name in NETWORK_TOOL_NAMES or tool_name in SHELL_TOOL_NAMES


def _entry_matches_hint(entry: ParameterEntry, hint_keys: set[str]) -> bool:
    path = entry.path.lower()
    return any(path.endswith(key) or f".{key}" in path for key in hint_keys)


def _match_dangerous_commands(
    tool_name: str,
    flattened: list[ParameterEntry],
    combined_text: str,
) -> list[ThreatMatch]:
    should_scan_prompt = bool(combined_text) and (
        _tool_can_execute_commands(tool_name) or bool(EXECUTION_INTENT_PATTERN.search(combined_text))
    )
    if (
        not should_scan_prompt
        and not _tool_can_execute_commands(tool_name)
        and not any(_entry_matches_hint(entry, COMMAND_PARAMETER_KEYS) for entry in flattened)
    ):
        return []

    matches: list[ThreatMatch] = []
    for entry in flattened:
        if not _entry_matches_hint(entry, COMMAND_PARAMETER_KEYS):
            continue
        for rule_name, pattern, score, category, reason in COMMAND_DESTRUCTIVE_PATTERNS:
            match = pattern.search(entry.value_text)
            if match:
                matches.append(
                    ThreatMatch(
                        rule_name=rule_name,
                        category=category,
                        score=score,
                        evidence=f"{entry.path}={match.group(0)[:200]}",
                        reason=reason,
                    )
                )
    if should_scan_prompt:
        for rule_name, pattern, score, category, reason in COMMAND_DESTRUCTIVE_PATTERNS:
            match = pattern.search(combined_text)
            if match:
                matches.append(
                    ThreatMatch(
                        rule_name=rule_name,
                        category=category,
                        score=score,
                        evidence=f"prompt_context={match.group(0)[:200]}",
                        reason=reason,
                    )
                )
    return matches


def _match_sensitive_files(
    tool_name: str,
    flattened: list[ParameterEntry],
    combined_text: str,
) -> list[ThreatMatch]:
    should_scan_prompt = bool(combined_text) and (
        _tool_can_access_files(tool_name) or bool(ACCESS_INTENT_PATTERN.search(combined_text))
    )
    if (
        not should_scan_prompt
        and not _tool_can_access_files(tool_name)
        and not any(_entry_matches_hint(entry, FILE_PARAMETER_KEYS) for entry in flattened)
    ):
        return []

    matches: list[ThreatMatch] = []
    for entry in flattened:
        if not _entry_matches_hint(entry, FILE_PARAMETER_KEYS):
            continue
        for rule_name, pattern, score, category, reason in SENSITIVE_FILE_PATTERNS:
            match = pattern.search(entry.value_text)
            if match:
                matches.append(
                    ThreatMatch(
                        rule_name=rule_name,
                        category=category,
                        score=score,
                        evidence=f"{entry.path}={match.group(0)[:200]}",
                        reason=reason,
                    )
                )
    if should_scan_prompt:
        for rule_name, pattern, score, category, reason in SENSITIVE_FILE_PATTERNS:
            match = pattern.search(combined_text)
            if match:
                matches.append(
                    ThreatMatch(
                        rule_name=rule_name,
                        category=category,
                        score=score,
                        evidence=f"prompt_context={match.group(0)[:200]}",
                        reason=reason,
                    )
                )
    return matches


def _match_internal_targets(
    tool_name: str,
    flattened: list[ParameterEntry],
    combined_text: str,
) -> list[ThreatMatch]:
    should_scan_prompt = bool(combined_text) and (
        _tool_can_access_network(tool_name) or bool(ACCESS_INTENT_PATTERN.search(combined_text))
    )
    if (
        not should_scan_prompt
        and not _tool_can_access_network(tool_name)
        and not any(_entry_matches_hint(entry, NETWORK_PARAMETER_KEYS) for entry in flattened)
    ):
        return []

    matches: list[ThreatMatch] = []
    for entry in flattened:
        if not (
            _entry_matches_hint(entry, NETWORK_PARAMETER_KEYS)
            or _entry_matches_hint(entry, COMMAND_PARAMETER_KEYS)
        ):
            continue
        for rule_name, pattern, score, category, reason in INTERNAL_TARGET_PATTERNS:
            match = pattern.search(entry.value_text)
            if match:
                matches.append(
                    ThreatMatch(
                        rule_name=rule_name,
                        category=category,
                        score=score,
                        evidence=f"{entry.path}={match.group(0)[:200]}",
                        reason=reason,
                    )
                )
    if should_scan_prompt:
        for rule_name, pattern, score, category, reason in INTERNAL_TARGET_PATTERNS:
            match = pattern.search(combined_text)
            if match:
                matches.append(
                    ThreatMatch(
                        rule_name=rule_name,
                        category=category,
                        score=score,
                        evidence=f"prompt_context={match.group(0)[:200]}",
                        reason=reason,
                    )
                )
    return matches


def _match_privilege_escalation(
    tool_name: str,
    flattened: list[ParameterEntry],
    combined_text: str,
) -> list[ThreatMatch]:
    matches: list[ThreatMatch] = []

    text_candidates = [combined_text]
    if _tool_can_execute_commands(tool_name):
        text_candidates.extend(entry.value_text for entry in flattened)
    else:
        text_candidates.extend(
            entry.value_text
            for entry in flattened
            if _entry_matches_hint(entry, COMMAND_PARAMETER_KEYS)
            or _entry_matches_hint(entry, FILE_PARAMETER_KEYS)
        )

    for candidate in text_candidates:
        if not candidate:
            continue
        for rule_name, pattern, score, category, reason in PRIVILEGE_ESCALATION_PATTERNS:
            match = pattern.search(candidate)
            if match:
                matches.append(
                    ThreatMatch(
                        rule_name=rule_name,
                        category=category,
                        score=score,
                        evidence=match.group(0)[:200],
                        reason=reason,
                    )
                )

    return matches


def _match_secret_exfiltration(
    tool_name: str,
    flattened: list[ParameterEntry],
    combined_text: str,
) -> list[ThreatMatch]:
    matches: list[ThreatMatch] = []
    candidate_texts = [combined_text]
    candidate_texts.extend(entry.value_text for entry in flattened)

    joined_text = "\n".join(text for text in candidate_texts if text)
    if not joined_text:
        return matches

    has_secret_reference = any(pattern.search(joined_text) for pattern in SECRET_TEXT_PATTERNS)
    has_exfil_action = bool(EXFIL_ACTION_PATTERN.search(joined_text))
    has_remote_sink = bool(EXFIL_DESTINATION_PATTERN.search(joined_text))

    if has_secret_reference and (has_exfil_action or has_remote_sink):
        evidence_parts: list[str] = []
        for pattern in SECRET_TEXT_PATTERNS:
            match = pattern.search(joined_text)
            if match:
                evidence_parts.append(match.group(0))
                break
        action_match = EXFIL_ACTION_PATTERN.search(joined_text)
        if action_match:
            evidence_parts.append(action_match.group(0))
        sink_match = EXFIL_DESTINATION_PATTERN.search(joined_text)
        if sink_match:
            evidence_parts.append(sink_match.group(0))

        matches.append(
            ThreatMatch(
                rule_name="secret_exfiltration_attempt",
                category="secret_exfiltration",
                score=0.96 if _tool_can_access_network(tool_name) or _tool_can_execute_commands(tool_name) else 0.92,
                evidence=" | ".join(evidence_parts)[:240],
                reason="Sensitive data exfiltration attempt detected.",
            )
        )

    return matches
