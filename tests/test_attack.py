"""MITRE ATT&CK dataset and tag resolution."""

from __future__ import annotations

import pytest

from custos_vulnerum.attack import load_techniques, resolve, technique_ids_from_tags
from custos_vulnerum.errors import DetectionError


def test_dataset_has_expected_techniques() -> None:
    techniques = load_techniques()
    assert set(techniques) == {"T1190", "T1059.004"}
    t1190 = techniques["T1190"]
    assert t1190.name == "Exploit Public-Facing Application"
    assert t1190.tactic_id == "TA0001"
    assert t1190.url == "https://attack.mitre.org/techniques/T1190/"
    assert "Enterprise" in t1190.source
    assert techniques["T1059.004"].tactic_name == "Execution"


def test_tag_extraction() -> None:
    tags = [
        "attack.initial_access",
        "attack.t1190",
        "attack.execution",
        "attack.t1059.004",
        "cve.2021",
    ]
    assert technique_ids_from_tags(tags) == ["T1190", "T1059.004"]
    assert technique_ids_from_tags(["attack.initial_access"]) == []
    assert technique_ids_from_tags([]) == []


def test_resolve_requires_dataset_rows() -> None:
    techniques = load_techniques()
    assert [t.technique_id for t in resolve(["T1190"], techniques)] == ["T1190"]
    with pytest.raises(DetectionError, match="missing from"):
        resolve(["T9999"], techniques)
