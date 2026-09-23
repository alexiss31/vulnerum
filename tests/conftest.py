"""Shared fixtures for the unit test suite (no Docker required)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from custos_vulnerum.catalog import LoadedLab, get_lab
from custos_vulnerum.config import Paths

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def repo_paths() -> Paths:
    return Paths.resolve(root=REPO_ROOT)


@pytest.fixture()
def apache_lab(repo_paths: Paths) -> LoadedLab:
    return get_lab(repo_paths, "cve-2021-41773")


@pytest.fixture()
def log4j_lab(repo_paths: Paths) -> LoadedLab:
    return get_lab(repo_paths, "cve-2021-44228")


def minimal_lab_dict(**overrides: Any) -> dict[str, Any]:
    """A minimal valid lab.yaml mapping for model-level tests."""
    raw: dict[str, Any] = {
        "id": "cve-2020-0001",
        "title": "Test lab",
        "summary": "Test summary",
        "cve": "CVE-2020-0001",
        "cvss": 5.0,
        "severity": "medium",
        "vendor": "Test",
        "component": "Test component",
        "affected_versions": "1.0",
        "fixed_versions": "1.1",
        "references": ["https://example.invalid/advisory"],
        "attack": [{"technique_id": "T1190", "role": "test"}],
        "compose": {
            "file": "compose.yaml",
            "mitigated_file": "compose.mitigated.yaml",
            "project": "custos-cve-2020-0001",
            "target_service": "app",
            "port": 18081,
            "container_port": 8080,
        },
        "logsource": {"category": "webserver", "product": "test", "service": "app"},
        "verification": [{"kind": "http_status", "value": "200"}],
        "poc": {
            "steps": [
                {
                    "type": "http",
                    "name": "baseline",
                    "role": "act",
                    "path": "/",
                    "expect_status": [200],
                },
                {
                    "type": "http",
                    "name": "proof",
                    "role": "proof",
                    "path": "/exploit",
                    "expect_status": [200],
                    "expect_body": ["pwned"],
                },
            ]
        },
        "evidence": {"log_rules": [{"service": "app", "contains": ["ERROR"]}]},
        "detection_rules": [],
        "mitigation_notes": "mitigation.md",
    }
    raw.update(overrides)
    return raw
