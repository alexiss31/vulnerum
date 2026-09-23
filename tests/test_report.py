"""Report rendering: honest lifecycle narrative from real artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from custos_vulnerum.models import AttackTechnique, EvidenceRun
from custos_vulnerum.report import build_context, render_reports, write_reports

from .test_evidence import _sample_run


def _retest_run() -> EvidenceRun:
    run = _sample_run()
    updates = run.model_dump()
    updates.update(
        {
            "run_id": "20260923T103000Z",
            "phase": "retest",
            "environment": "mitigated",
            "result": "not_vulnerable",
        }
    )
    for step in updates["steps"]:
        step["indicators_met"] = False
        step["canary"] = (
            {"checked": True, "matched": False, "matched_lines": [], "observed_at": None}
            if step["canary"]
            else None
        )
    return EvidenceRun.model_validate(updates)


def _technique() -> AttackTechnique:
    return AttackTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        url="https://attack.mitre.org/techniques/T1190/",
        source="MITRE ATT&CK Enterprise v19 (test)",
    )


def test_report_renders_full_lifecycle(log4j_lab: Any) -> None:
    poc_run = _sample_run()
    context = build_context(
        log4j_lab,
        poc_run,
        _retest_run(),
        None,
        None,
        [_technique()],
    )
    markdown, html = render_reports(context)
    for needle in (
        "CVE-2021-44228",
        "vulnerable",
        "not_vulnerable",
        "Mitigation effective: verified",
        "T1190",
        "Exploit Public-Facing Application",
        poc_run.token,
    ):
        assert needle in markdown
        assert needle in html
    assert "Not run — `custos verify cve-2021-44228`" in markdown


def test_report_marks_missing_stages_not_run(log4j_lab: Any) -> None:
    context = build_context(log4j_lab, None, None, None, None, [])
    markdown, _ = render_reports(context)
    assert "not run" in markdown
    assert "Mitigation not retested" in markdown


def test_write_reports_outputs_files(log4j_lab: Any, tmp_path: Path) -> None:
    context = build_context(log4j_lab, _sample_run(), None, None, None, [_technique()])
    markdown, html = render_reports(context)
    md_path, html_path = write_reports(tmp_path, markdown, html)
    assert md_path.read_text(encoding="utf-8") == markdown
    assert html_path.read_text(encoding="utf-8") == html
