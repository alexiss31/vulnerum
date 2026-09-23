"""Evidence artifacts: contract compliance, roundtrip and event derivation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from custos_vulnerum import evidence
from custos_vulnerum.config import Paths
from custos_vulnerum.models import (
    CanaryObservation,
    EvidenceRun,
    LogExcerpt,
    RequestRecord,
    ResponseRecord,
    StepEvidence,
    VerificationCheckResult,
    VerificationReport,
)

from .conftest import REPO_ROOT

SCHEMA_PATH = REPO_ROOT / "specs" / "001-vulnerum-core" / "contracts" / "evidence.schema.json"


def _sample_run() -> EvidenceRun:
    now = datetime(2026, 9, 23, 10, 0, 0, tzinfo=UTC)
    step = StepEvidence(
        name="proof",
        type="http",
        role="proof",
        expected="status in [200]",
        indicators_met=True,
        request=RequestRecord(
            method="GET",
            url="http://127.0.0.1:8917/icons/.%2e/etc/passwd",
            headers={"user-agent": "custos"},
            body_excerpt="",
            sent_at=now,
        ),
        response=ResponseRecord(status=200, body_excerpt="root:x:0:0", received_at=now),
        logs=[LogExcerpt(service="httpd", lines=['"GET /icons/.%2e/etc/passwd HTTP/1.1" 200'])],
    )
    canary_step = StepEvidence(
        name="canary",
        type="canary_ldap",
        role="proof",
        expected="token captured",
        indicators_met=True,
        logs=[LogExcerpt(service="canary", lines=["CANARY connection from 10.0.0.2"])],
        canary=CanaryObservation(
            checked=True,
            matched=True,
            matched_lines=["CANARY connection from 10.0.0.2"],
            observed_at=now,
        ),
    )
    return EvidenceRun(
        run_id="20260923T100000Z",
        lab_id="cve-2021-44228",
        cve="CVE-2021-44228",
        phase="poc",
        environment="vulnerable",
        started_at=now,
        finished_at=now,
        token="custos-aabbcc",
        result="vulnerable",
        steps=[step, canary_step],
    )


def test_evidence_matches_published_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(_sample_run().model_dump(mode="json"), schema)


def test_evidence_roundtrip(tmp_path: Path) -> None:
    paths = Paths(
        root=tmp_path,
        labs=tmp_path / "labs",
        detection=tmp_path / "detection",
        sigma=tmp_path / "detection/sigma",
        wazuh=tmp_path / "detection/wazuh",
        artifacts=tmp_path / "artifacts",
    )
    run = _sample_run()
    run_dir = evidence.write_evidence(paths, run)
    loaded = evidence.read_evidence(run_dir)
    assert loaded == run
    assert evidence.find_run(paths, run.lab_id, "poc") == run_dir
    assert evidence.find_run(paths, run.lab_id, "retest") is None


def test_derive_events_lab_logsource_and_canary(log4j_lab: Any) -> None:
    events = evidence.derive_events(_sample_run(), log4j_lab.meta.logsource)
    request_events = [e for e in events if e["source"] == "request"]
    canary_events = [e for e in events if e["source"] == "canary"]
    log_events = [e for e in events if e["source"] == "log"]
    assert request_events and log_events and canary_events
    assert request_events[0]["product"] == "log4j"
    assert request_events[0]["service"] == "webapp"
    assert request_events[0]["http_path"] == "/icons/.%2e/etc/passwd"
    assert canary_events[0]["product"] == "custos"
    assert canary_events[0]["service"] == "ldap_canary"
    assert log_events[0]["message"].startswith('"GET')


def test_verification_roundtrip(tmp_path: Path) -> None:
    paths = Paths(
        root=tmp_path,
        labs=tmp_path / "labs",
        detection=tmp_path / "detection",
        sigma=tmp_path / "detection/sigma",
        wazuh=tmp_path / "detection/wazuh",
        artifacts=tmp_path / "artifacts",
    )
    record = VerificationReport(
        lab_id="cve-2021-41773",
        variant="vulnerable",
        checked_at=datetime.now(UTC),
        passed=True,
        checks=[
            VerificationCheckResult(
                kind="http_status",
                description="answers",
                expected="200",
                observed="200",
                passed=True,
            )
        ],
    )
    evidence.write_verification(paths, record)
    assert evidence.read_verification(paths, "cve-2021-41773", "vulnerable") == record
    assert evidence.read_verification(paths, "cve-2021-41773", "mitigated") is None
