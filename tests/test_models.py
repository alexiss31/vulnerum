"""Lab metadata and evidence models (contracts/lab-schema.md)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from custos_vulnerum.models import LabMeta, VerificationCheck

from .conftest import minimal_lab_dict


def test_minimal_lab_validates() -> None:
    meta = LabMeta.model_validate(minimal_lab_dict())
    assert meta.id == "cve-2020-0001"
    assert meta.severity == "medium"
    assert len(meta.poc.steps) == 2


def test_shipped_labs_validate(apache_lab: Any, log4j_lab: Any) -> None:
    assert apache_lab.meta.cve == "CVE-2021-41773"
    assert apache_lab.meta.compose.port == 8917
    assert log4j_lab.meta.cve == "CVE-2021-44228"
    assert log4j_lab.meta.canary is not None
    assert log4j_lab.meta.canary.port == 1389


def test_unknown_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        LabMeta.model_validate(minimal_lab_dict(surprise="nope"))


def test_bad_cve_rejected() -> None:
    with pytest.raises(ValidationError):
        LabMeta.model_validate(minimal_lab_dict(cve="NOT-A-CVE"))


def test_bad_technique_rejected() -> None:
    raw = minimal_lab_dict()
    raw["attack"] = [{"technique_id": "X9999", "role": "test"}]
    with pytest.raises(ValidationError):
        LabMeta.model_validate(raw)


def test_plan_needs_proof_step() -> None:
    raw = minimal_lab_dict()
    raw["poc"]["steps"] = [
        {"type": "http", "name": "a", "role": "act", "path": "/", "expect_status": [200]}
    ]
    with pytest.raises(ValidationError):
        LabMeta.model_validate(raw)


def test_canary_use_requires_canary_spec() -> None:
    raw = minimal_lab_dict()
    raw["poc"]["steps"].append(
        {
            "type": "http",
            "name": "trigger",
            "role": "act",
            "path": "/x?h={canary_host}",
            "expect_status": [200],
        }
    )
    with pytest.raises(ValidationError):
        LabMeta.model_validate(raw)


def test_verification_expected_value_override() -> None:
    check = VerificationCheck(kind="server_marker", value="2.4.49", value_mitigated="2.4.51")
    assert check.expected_value(False) == "2.4.49"
    assert check.expected_value(True) == "2.4.51"
    plain = VerificationCheck(kind="http_status", value="200")
    assert plain.expected_value(True) == "200"
