"""Lifecycle report rendering (Markdown + HTML) via Jinja2."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from . import __version__
from .catalog import LoadedLab
from .models import AttackTechnique, EvidenceRun, VerificationReport

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def build_context(
    lab: LoadedLab,
    poc_run: EvidenceRun | None,
    retest_run: EvidenceRun | None,
    verify_vulnerable: VerificationReport | None,
    verify_mitigated: VerificationReport | None,
    techniques: list[AttackTechnique],
) -> dict[str, Any]:
    """Assemble everything a report needs; missing stages stay explicitly 'not run'."""
    mitigation_effective: str | None = None
    if poc_run is not None and retest_run is not None:
        if poc_run.result == "vulnerable" and retest_run.result == "not_vulnerable":
            mitigation_effective = "verified"
        else:
            mitigation_effective = "not verified"
    return {
        "lab": lab.meta,
        "mitigation_text": lab.mitigation_path().read_text(encoding="utf-8"),
        "poc_run": poc_run,
        "retest_run": retest_run,
        "verify_vulnerable": verify_vulnerable,
        "verify_mitigated": verify_mitigated,
        "detections": (poc_run.detections if poc_run else [])
        + (retest_run.detections if retest_run else []),
        "techniques": techniques,
        "mitigation_effective": mitigation_effective,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool_version": __version__,
    }


def render_reports(context: dict[str, Any]) -> tuple[str, str]:
    """Render (report.md, report.html) from one context."""
    # B701 acknowledged: Markdown output has no HTML context; the HTML environment
    # below enables autoescape explicitly.
    md_env = Environment(  # markdown-only rendering  # nosec B701
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    html_env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    markdown = md_env.get_template("report.md.j2").render(**context)
    html = html_env.get_template("report.html.j2").render(**context)
    return markdown, html


def write_reports(directory: Path, markdown: str, html: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    md_path = directory / "report.md"
    html_path = directory / "report.html"
    md_path.write_text(markdown, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")
    return md_path, html_path
