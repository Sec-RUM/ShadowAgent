"""Response-side DLP tests: non-streaming modes, streaming hold-back, suppression."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.dlp import (
    BUILTIN_DLP_PATTERNS,
    ScanOutcome,
    StreamingDlpScanner,
    apply_redactions,
    response_dlp_mode,
    scan_text,
)
from models import CustomRule

_DLP_CHAT = {
    "model": "shadow-agent-simulated",
    "messages": [{"role": "user", "content": "summarize the following export, __dlp_demo__"}],
}


@pytest.fixture
def dlp_mode(monkeypatch: pytest.MonkeyPatch):
    def _set(mode: str) -> None:
        monkeypatch.setenv("SHADOW_AGENT_RESPONSE_DLP_MODE", mode)

    # Isolate the response-side DLP layer from the request-side semantic engine
    # so these tests exercise DLP behavior regardless of ML-layer tuning.
    monkeypatch.setenv("SHADOW_AGENT_SEMANTIC_MODE", "off")
    _set("redact")
    yield _set
    monkeypatch.delenv("SHADOW_AGENT_RESPONSE_DLP_MODE", raising=False)
    monkeypatch.delenv("SHADOW_AGENT_SEMANTIC_MODE", raising=False)


def _rule(**overrides: Any) -> CustomRule:
    values = {
        "name": "resp-rule",
        "description": "",
        "rule_type": "regex",
        "pattern": r"PROJECT[- ]XRAY[- ]\d+",
        "target": "response",
        "action": "redact",
        "risk_score": 0.7,
        "enabled": True,
    }
    values.update(overrides)
    return CustomRule(**values)


# --- unit: patterns & redaction ---------------------------------------------


def test_builtin_patterns_detect_each_secret_type() -> None:
    samples = {
        "aws_access_key": "key AKIAIOSFODNN7EXAMPLE here",
        "github_token": "token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDE here",
        "openai_style_key": "key sk-proj-abcdefghij1234567890abcdefghij here",
        "slack_token": "token xoxb-1234567890abcdefghijkl here",
        "google_api_key": "key AIzaSyA1234567890abcdefghijklmnopqrstuv here",
        "jwt_token": "jwt eyJhbGciOiJIUz.eyJzdWIiOiIxMjM0NTY3O.SflKxwRJSMeKKF2QT4 here",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
        "secret_assignment": "config api_key = abcdefghijklmnopqrstuvwx",
    }
    for expected_type, text in samples.items():
        outcome = scan_text(text, [])
        matched_types = {match.match_type for match in outcome.matches}
        assert expected_type in matched_types, f"{expected_type} not detected in {text!r}"


def test_clean_text_has_no_matches() -> None:
    outcome = scan_text("Here is a normal, helpful answer about OAuth best practices.", [])
    assert outcome.matches == []


def test_apply_redactions_replaces_spans() -> None:
    text = "prefix AKIAIOSFODNN7EXAMPLE suffix"
    outcome = scan_text(text, [])
    redacted = apply_redactions(text, outcome)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED:aws_access_key]" in redacted
    assert redacted.startswith("prefix ")
    assert redacted.endswith(" suffix")


def test_custom_response_rule_adds_redaction() -> None:
    text = "internal codename: PROJECT XRAY 4711 over"
    outcome = scan_text(text, [_rule()])
    assert outcome.has_redactions
    redacted = apply_redactions(text, outcome)
    assert "PROJECT XRAY 4711" not in redacted
    assert "[REDACTED:resp-rule]" in redacted


def test_custom_block_rule_forces_block_flag() -> None:
    outcome = scan_text("PROJECT XRAY 4711", [_rule(action="block")])
    assert outcome.should_block is True


# --- unit: streaming scanner ------------------------------------------------


def test_streaming_scanner_catches_secret_split_across_chunks() -> None:
    scanner = StreamingDlpScanner(mode="redact", rules=[], request_id="t1")
    out1 = scanner.feed("export: AKIAIOSFODN")
    out2 = scanner.feed("N7EXAMPLE ok")
    out3 = scanner.finish()
    combined = out1 + out2 + out3
    assert "AKIAIOSFODNN7EXAMPLE" not in combined
    assert "[REDACTED:aws_access_key]" in combined
    assert "export: " in combined and "ok" in combined


def test_streaming_scanner_monitor_mode_passes_through() -> None:
    scanner = StreamingDlpScanner(mode="monitor", rules=[], request_id="t2")
    combined = scanner.feed("AKIAIOSFODNN7EXAMPLE") + scanner.finish()
    assert combined == "AKIAIOSFODNN7EXAMPLE"
    assert scanner.matches  # still recorded for logging


def test_streaming_scanner_private_key_suppression() -> None:
    scanner = StreamingDlpScanner(mode="redact", rules=[], request_id="t3")
    out = scanner.feed("here\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpA\n")
    out += scanner.feed("more secret material\n")
    out += scanner.feed("-----END RSA PRIVATE KEY-----\nafter")
    out += scanner.finish()
    assert "MIIEpA" not in out
    assert "more secret material" not in out
    assert "[REDACTED:private_key]" in out
    assert "after" in out


def test_streaming_scanner_block_mode_terminates() -> None:
    scanner = StreamingDlpScanner(mode="block", rules=[], request_id="t4")
    emitted = scanner.feed("here comes AKIAIOSFODNN7EXAMPLE now")
    assert emitted == ""
    assert scanner.blocked is True
    payload = scanner.blocked_payload()
    assert payload["layer"] == "response_dlp"
    assert payload["reason"] == "sensitive_data_detected_in_model_output"


def test_streaming_scanner_unterminated_key_stays_suppressed() -> None:
    scanner = StreamingDlpScanner(mode="redact", rules=[], request_id="t5")
    out = scanner.feed("-----BEGIN PRIVATE KEY-----\nMIIEo")
    out += scanner.finish()
    assert "MIIEo" not in out
    assert "[REDACTED:private_key]" in out


# --- integration: gateway non-streaming --------------------------------------


def test_nonstream_redact_mode(
    client: TestClient,
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("redact")
    response = client.post("/api/v1/chat/completions", headers=client_headers, json=_DLP_CHAT)
    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert "AKIAIOSFODNN7EXAMPLE" not in content
    assert "ghp_abcdefghij" not in content
    assert "[REDACTED:aws_access_key]" in content
    assert "[REDACTED:github_token]" in content
    assert "[REDACTED:openai_style_key]" in content
    dlp_meta = response.json().get("shadow_agent", {}).get("response_dlp")
    assert dlp_meta is not None and dlp_meta["mode"] == "redact"


def test_nonstream_monitor_mode_passes_through(
    client: TestClient,
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("monitor")
    response = client.post("/api/v1/chat/completions", headers=client_headers, json=_DLP_CHAT)
    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert "AKIAIOSFODNN7EXAMPLE" in content  # unchanged
    assert "[REDACTED" not in content


def test_nonstream_block_mode_returns_403(
    client: TestClient,
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("block")
    response = client.post("/api/v1/chat/completions", headers=client_headers, json=_DLP_CHAT)
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["layer"] == "response_dlp"
    assert detail["category"] == "secret_exfiltration"


def test_nonstream_off_mode_skips_scan(
    client: TestClient,
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("off")
    response = client.post("/api/v1/chat/completions", headers=client_headers, json=_DLP_CHAT)
    assert response.status_code == 200
    assert "AKIAIOSFODNN7EXAMPLE" in response.json()["choices"][0]["message"]["content"]


def test_dlp_intercept_log_recorded(
    client: TestClient,
    admin_headers: dict[str, str],
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("redact")
    client.post("/api/v1/chat/completions", headers=client_headers, json=_DLP_CHAT)
    logs = client.get("/api/v1/logs?limit=20", headers=admin_headers).json()
    dlp_logs = [
        item
        for item in logs.get("items", [])
        if item.get("threat_type") == "Data Exfiltration"
    ]
    assert dlp_logs, "expected a DLP intercept log entry"
    assert dlp_logs[0]["action_taken"] == "Redacted"


# --- integration: gateway streaming ------------------------------------------


def _read_stream(response) -> str:
    content_parts: list[str] = []
    error_payload = None
    for line in response.iter_lines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            event = json.loads(data)
        except ValueError:
            continue
        if isinstance(event, dict) and "error" in event:
            error_payload = event["error"]
            continue
        choices = event.get("choices") or []
        if choices and isinstance(choices[0].get("delta"), dict):
            content_parts.append(choices[0]["delta"].get("content", ""))
    return "".join(content_parts), error_payload


def test_stream_redact_catches_split_secret(
    client: TestClient,
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("redact")
    with client.stream(
        "POST",
        "/api/v1/chat/completions",
        headers=client_headers,
        json={**_DLP_CHAT, "stream": True},
    ) as response:
        assert response.status_code == 200
        combined, error = _read_stream(response)
    assert error is None
    assert "AKIAIOSFODNN7EXAMPLE" not in combined
    assert "[REDACTED:aws_access_key]" in combined


def test_stream_block_mode_emits_error_frame(
    client: TestClient,
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("block")
    with client.stream(
        "POST",
        "/api/v1/chat/completions",
        headers=client_headers,
        json={**_DLP_CHAT, "stream": True},
    ) as response:
        assert response.status_code == 200
        combined, error = _read_stream(response)
    assert error is not None
    assert error["layer"] == "response_dlp"
    assert "AKIA" not in combined


def test_stream_clean_content_untouched(
    client: TestClient,
    client_headers: dict[str, str],
    dlp_mode,
) -> None:
    dlp_mode("redact")
    payload = {
        "model": "shadow-agent-simulated",
        "messages": [{"role": "user", "content": "just a normal stream"}],
        "stream": True,
    }
    with client.stream(
        "POST",
        "/api/v1/chat/completions",
        headers=client_headers,
        json=payload,
    ) as response:
        combined, error = _read_stream(response)
    assert error is None
    assert combined == "mock stream ok"


def test_response_dlp_mode_env_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHADOW_AGENT_RESPONSE_DLP_MODE", "bogus")
    assert response_dlp_mode() == "redact"
    monkeypatch.setenv("SHADOW_AGENT_RESPONSE_DLP_MODE", "MONITOR")
    assert response_dlp_mode() == "monitor"
