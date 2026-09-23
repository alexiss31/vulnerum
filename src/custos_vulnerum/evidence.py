"""Normalized evidence: artifact I/O and detection-event derivation.

Artifact layout (git-ignored runtime output): ``artifacts/<lab_id>/<run_id>/`` with
``evidence.json``, ``detections.json``, ``report.md`` and ``report.html``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from .config import Paths
from .errors import EvidenceError
from .models import (
    DetectionMatch,
    EvidenceRun,
    LogSourceSpec,
    VerificationReport,
)

EVIDENCE_FILE = "evidence.json"
DETECTIONS_FILE = "detections.json"

CANARY_LOGSOURCE = {"category": "network", "product": "custos", "service": "ldap_canary"}


def utc_now() -> datetime:
    return datetime.now(UTC)


def make_run_id(now: datetime | None = None) -> str:
    moment = (now or utc_now()).astimezone(UTC)
    return moment.strftime("%Y%m%dT%H%M%SZ")


def run_dir(paths: Paths, lab_id: str, run_id: str) -> Path:
    return paths.artifacts / lab_id / run_id


def write_evidence(paths: Paths, run: EvidenceRun) -> Path:
    """Persist one evidence run and return its directory."""
    target = run_dir(paths, run.lab_id, run.run_id)
    target.mkdir(parents=True, exist_ok=True)
    (target / EVIDENCE_FILE).write_text(
        json.dumps(run.model_dump(mode="json"), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return target


def read_evidence(path: Path) -> EvidenceRun:
    """Read an evidence run from a file or from its run directory."""
    evidence_file = path / EVIDENCE_FILE if path.is_dir() else path
    if not evidence_file.is_file():
        raise EvidenceError(f"no evidence file at {evidence_file}")
    try:
        raw = json.loads(evidence_file.read_text(encoding="utf-8"))
        return EvidenceRun.model_validate(raw)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise EvidenceError(f"unreadable evidence at {evidence_file}: {exc}") from exc


def write_detections(directory: Path, matches: list[DetectionMatch]) -> Path:
    target = directory / DETECTIONS_FILE
    payload = [match.model_dump(mode="json") for match in matches]
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


_VERIFICATION_DIR = "_verification"


def write_verification(paths: Paths, report: VerificationReport) -> Path:
    """Persist a verify record at ``artifacts/<lab>/_verification/<variant>.json``."""
    target = paths.artifacts / report.lab_id / _VERIFICATION_DIR
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{report.variant}.json"
    path.write_text(json.dumps(report.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    return path


def read_verification(paths: Paths, lab_id: str, variant: str) -> VerificationReport | None:
    path = paths.artifacts / lab_id / _VERIFICATION_DIR / f"{variant}.json"
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return VerificationReport.model_validate(raw)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise EvidenceError(f"unreadable verification record at {path}: {exc}") from exc


def find_run(paths: Paths, lab_id: str, phase: str) -> Path | None:
    """Latest run directory for a lab and phase (poc|retest), or None."""
    lab_dir = paths.artifacts / lab_id
    if not lab_dir.is_dir():
        return None
    candidates: list[Path] = []
    for entry in sorted(lab_dir.iterdir()):
        if not entry.is_dir() or not (entry / EVIDENCE_FILE).is_file():
            continue
        run = read_evidence(entry)
        if run.phase == phase:
            candidates.append(entry)
    return candidates[-1] if candidates else None


def derive_events(run: EvidenceRun, lab_logsource: LogSourceSpec) -> list[dict[str, Any]]:
    """Normalize one run into detection events (see data-model.md).

    One event per request and one per selected log line. Request and log events carry
    the lab's declared logsource; canary hits carry their own (``product: custos``).
    Field names are the ones Sigma rules match on.
    """
    events: list[dict[str, Any]] = []
    base: dict[str, Any] = {
        "run_id": run.run_id,
        "lab_id": run.lab_id,
        "phase": run.phase,
        "environment": run.environment,
    }
    lab_source: dict[str, Any] = {
        "category": lab_logsource.category,
        "product": lab_logsource.product,
        "service": lab_logsource.service,
    }
    for step in run.steps:
        if step.request is not None:
            events.append(
                {
                    **base,
                    "timestamp": step.request.sent_at.isoformat(),
                    "source": "request",
                    **lab_source,
                    "http_method": step.request.method,
                    "http_path": _path_of(step.request.url),
                    "http_user_agent": step.request.headers.get("user-agent", ""),
                    "http_body": step.request.body_excerpt,
                    "status": step.response.status if step.response else None,
                    "message": "",
                    "container": "",
                }
            )
        for excerpt in step.logs:
            for line in excerpt.lines:
                events.append(
                    {
                        **base,
                        "timestamp": step.request.sent_at.isoformat()
                        if step.request
                        else run.started_at.isoformat(),
                        "source": "log",
                        **lab_source,
                        "http_method": "",
                        "http_path": "",
                        "http_user_agent": "",
                        "http_body": "",
                        "status": None,
                        "message": line,
                        "container": excerpt.service,
                    }
                )
        if step.canary is not None:
            for line in step.canary.matched_lines or (
                ["(canary captured token)"] if step.canary.matched else []
            ):
                events.append(
                    {
                        **base,
                        "timestamp": (
                            step.canary.observed_at.isoformat()
                            if step.canary.observed_at
                            else run.started_at.isoformat()
                        ),
                        "source": "canary",
                        **CANARY_LOGSOURCE,
                        "http_method": "",
                        "http_path": "",
                        "http_user_agent": "",
                        "http_body": "",
                        "status": None,
                        "message": line,
                        "container": "canary",
                    }
                )
    return events


def _path_of(url: str) -> str:
    parsed = urlsplit(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")
