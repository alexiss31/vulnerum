"""Docker end-to-end smoke: the full lifecycle for both labs through the real CLI.

Run with `make smoke`. Skipped (never faked) when the Docker daemon is unavailable.
Each lab: up → verify → PoC → detect → mitigated up → retest → report → down.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from custos_vulnerum.cli import app

runner = CliRunner()
LAB_IDS = ["cve-2021-41773", "cve-2021-44228"]
SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "specs"
    / "001-vulnerum-core"
    / "contracts"
    / "evidence.schema.json"
)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not _docker_available(), reason="Docker daemon unavailable"),
]


def _invoke(*args: str) -> None:
    result = runner.invoke(app, list(args))
    assert result.exit_code == 0, f"custos {' '.join(args)} failed:\n{result.output}"


@pytest.mark.parametrize("lab_id", LAB_IDS)
def test_full_lifecycle(lab_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import jsonschema

    monkeypatch.setenv("CUSTOS_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    runner.invoke(app, ["lab", "down", lab_id])  # clean slate (ok if not up)

    _invoke("lab", "up", lab_id)
    _invoke("verify", lab_id)
    _invoke("run", lab_id)
    _invoke("detect", lab_id)

    poc_evidence = _latest_evidence(tmp_path / "artifacts" / lab_id, "poc")
    jsonschema.validate(poc_evidence, schema)
    assert poc_evidence["result"] == "vulnerable"
    assert poc_evidence["detections"], "exploit evidence must fire at least one rule"
    assert poc_evidence["attack"], "ATT&CK mapping must be populated"

    _invoke("lab", "up", lab_id, "--mitigated")
    _invoke("run", lab_id, "--retest")
    retest_evidence = _latest_evidence(tmp_path / "artifacts" / lab_id, "retest")
    jsonschema.validate(retest_evidence, schema)
    assert retest_evidence["result"] == "not_vulnerable"
    assert retest_evidence["environment"] == "mitigated"

    if lab_id == "cve-2021-44228":
        _invoke("detect", lab_id, "--retest")
        retest_evidence = _latest_evidence(tmp_path / "artifacts" / lab_id, "retest")
        assert not any("canary" in match["rule_id"] for match in retest_evidence["detections"]), (
            "the canary-signal rule must stay silent after mitigation"
        )

    _invoke("report", lab_id)
    report_dir = tmp_path / "artifacts" / lab_id
    reports = sorted(report_dir.glob("*/report.md"))
    assert reports, "report.md must be written"
    report_text = reports[-1].read_text(encoding="utf-8")
    assert "Mitigation effective: verified" in report_text
    assert lab_id.replace("cve-", "CVE-") in report_text

    _invoke("lab", "down", lab_id)


def _latest_evidence(lab_dir: Path, phase: str) -> dict[str, Any]:
    latest: dict[str, Any] | None = None
    for run_dir in sorted(lab_dir.iterdir()):
        evidence_file = run_dir / "evidence.json"
        if not evidence_file.is_file():
            continue
        data: dict[str, Any] = json.loads(evidence_file.read_text(encoding="utf-8"))
        if data["phase"] == phase:
            latest = data
    assert latest is not None, f"no {phase} evidence under {lab_dir}"
    return latest
