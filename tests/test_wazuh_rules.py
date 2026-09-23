"""Optional Wazuh adapter: well-formed XML, sane ids, ATT&CK tags resolve."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from custos_vulnerum.attack import load_techniques
from custos_vulnerum.config import Paths


def test_wazuh_rules_parse_and_have_unique_ids(repo_paths: Paths) -> None:
    tree = ET.parse(repo_paths.wazuh / "local_rules.xml")
    rules = tree.findall(".//rule")
    assert len(rules) == 2
    ids = [int(rule.attrib["id"]) for rule in rules]
    assert len(set(ids)) == len(ids)
    assert all(rule_id >= 100000 for rule_id in ids)
    for rule in rules:
        assert rule.findtext("description")
        assert rule.find("pcre2") is not None


def test_wazuh_mitre_tags_resolve(repo_paths: Paths) -> None:
    techniques = load_techniques()
    tree = ET.parse(repo_paths.wazuh / "local_rules.xml")
    seen: set[str] = set()
    for mitre_id in tree.findall(".//mitre/id"):
        assert mitre_id.text is not None
        seen.add(mitre_id.text)
    assert {"T1190", "T1059.004"} <= seen
    assert seen <= set(techniques)


def test_wazuh_readme_documents_optional_status(repo_paths: Paths) -> None:
    readme = (repo_paths.wazuh / "README.md").read_text(encoding="utf-8")
    assert "does not require Wazuh" in readme
    assert "wazuh-logtest" in readme
