"""Security gates in CI must survive refactors.

``.github/workflows/ci.yml`` is where the project's claims are actually
enforced, and a deleted step fails silently: the build stays green and nothing
says the dependency scan stopped running. These assertions are cheap and they
turn "someone removed the gate" into a red test.

Only the gates that are easy to drop by accident are pinned here -- the test
matrix, migration check and image builds are visible in every PR anyway.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def workflow() -> str:
    assert CI_WORKFLOW.exists(), "CI workflow missing"
    return CI_WORKFLOW.read_text(encoding="utf-8")


def test_dependency_audit_job_exists(workflow: str) -> None:
    assert "dependency-audit:" in workflow, (
        "依赖漏洞扫描 job 被移除了 —— 它不会让别的测试变红，所以必须显式护栏"
    )


def test_backend_dependencies_are_audited_strictly(workflow: str) -> None:
    assert "pip-audit -r requirements.txt --strict" in workflow, (
        "后端依赖审计丢失或不再 --strict —— 解析失败会静默变成绿灯"
    )


def test_frontend_dependencies_are_audited(workflow: str) -> None:
    assert "npm audit --audit-level=high" in workflow, "前端依赖审计丢失"


def test_frontend_audit_is_blocking(workflow: str) -> None:
    """The frontend audit gates, same as the backend one.

    The tree carried real production advisories until the 2026-09-27 refresh
    cleared them (next 16.2.4 -> 16.3.6 and friends), so the step ran
    report-only with ``continue-on-error: true`` to avoid training people to
    ignore a permanently red gate. With the tree clean there is no reason for
    the exemption: if it ever comes back it should be a visible, justified
    edit -- never a silent one.
    """
    block = workflow.split("Audit frontend dependencies")[1]
    assert "continue-on-error" not in block.split("- name:")[0], (
        "前端审计又变回非阻断了 —— 依赖树自 2026-09-27 刷新后是干净的，"
        "豁免需要单独说明理由"
    )


def test_test_suite_and_frontend_build_are_still_gated(workflow: str) -> None:
    assert "python -m pytest tests -v" in workflow
    assert "npm run build" in workflow
