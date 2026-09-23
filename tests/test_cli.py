"""CLI surface and exit-code contract (no Docker required)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from custos_vulnerum.cli import app
from custos_vulnerum.lifecycle import LabEnvironment

runner = CliRunner()


def _no_docker(monkeypatch: Any) -> None:
    monkeypatch.setattr(LabEnvironment, "containers", lambda self: [])


def test_help_works() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for verb in ("list", "lab", "verify", "run", "detect", "report"):
        assert verb in result.output


def test_list_shows_shipped_labs(monkeypatch: Any) -> None:
    _no_docker(monkeypatch)
    result = runner.invoke(app, ["list"], env={"COLUMNS": "220"})
    assert result.exit_code == 0
    assert "cve-2021-41773" in result.output
    assert "cve-2021-44228" in result.output
    assert "down" in result.output


def test_unknown_lab_fails_cleanly() -> None:
    result = runner.invoke(app, ["verify", "cve-1999-9999"])
    assert result.exit_code == 1
    assert "unknown lab" in result.output


def test_verify_on_stopped_lab_fails(monkeypatch: Any) -> None:
    _no_docker(monkeypatch)
    result = runner.invoke(app, ["verify", "cve-2021-41773"])
    assert result.exit_code == 1
    assert "is not running" in result.output


def test_run_without_lab_fails_before_any_traffic(monkeypatch: Any) -> None:
    _no_docker(monkeypatch)
    result = runner.invoke(app, ["run", "cve-2021-41773"])
    assert result.exit_code == 1
    assert "is not running" in result.output


def test_detect_without_evidence_fails(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("CUSTOS_ARTIFACTS_DIR", str(tmp_path))
    result = runner.invoke(app, ["detect", "cve-2021-41773"])
    assert result.exit_code == 1
    assert "no poc evidence" in result.output


def test_report_without_evidence_fails(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("CUSTOS_ARTIFACTS_DIR", str(tmp_path))
    result = runner.invoke(app, ["report", "cve-2021-41773"])
    assert result.exit_code == 1
    assert "no evidence" in result.output
