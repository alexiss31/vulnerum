"""Sigma rule contract tests.

Rules must (1) validate against the official Sigma JSON schema v2.0.0 (vendored from
SigmaHQ/sigma-specification, fetched 2026-09-23), (2) parse under current SigmaHQ
tooling (pySigma), and (3) carry ATT&CK tags that resolve in the local dataset. CI
additionally converts every rule through sigma-cli with a real pySigma backend.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import jsonschema
import yaml
from sigma.collection import SigmaCollection

from custos_vulnerum.attack import load_techniques, resolve, technique_ids_from_tags
from custos_vulnerum.detection import load_rule_file

from .conftest import REPO_ROOT

SCHEMA_PATH = REPO_ROOT / "tests" / "fixtures" / "sigma-rule-schema.v2.0.0.json"
RULE_DIRS = [
    REPO_ROOT / "detection" / "sigma",
    REPO_ROOT / "labs" / "_template",
]
FILENAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_.")


def _rule_files() -> list[Path]:
    files: list[Path] = []
    for directory in RULE_DIRS:
        files.extend(
            path
            for path in sorted(directory.iterdir())
            if path.suffix == ".yml" and path.name != "lab.yaml"
        )
    return files


def test_rule_files_found() -> None:
    names = {path.name for path in _rule_files()}
    assert "web_cve_2021_41773_apache_path_traversal.yml" in names
    assert "web_cve_2021_44228_log4shell_jndi_lookup.yml" in names
    assert "net_cve_2021_44228_log4shell_jndi_ldap_connection.yml" in names


def test_rules_validate_against_official_json_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for path in _rule_files():
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        jsonschema.validate(raw, schema)


def test_rules_parse_with_pysigma() -> None:
    for path in _rule_files():
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        assert len(collection.rules) == 1, path.name


def test_rules_have_unique_valid_uuids() -> None:
    seen: set[str] = set()
    for path in _rule_files():
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule_id = raw["id"]
        uuid.UUID(rule_id)  # raises if malformed
        assert rule_id not in seen, f"duplicate rule id in {path.name}"
        seen.add(rule_id)


def test_rule_filenames_follow_convention() -> None:
    for path in _rule_files():
        stem = path.stem
        assert 10 <= len(path.name) <= 70, path.name
        assert set(stem) <= FILENAME_CHARS, path.name
        assert stem.lower() == stem, path.name


def test_attack_tags_resolve_to_dataset() -> None:
    techniques = load_techniques()
    for path in _rule_files():
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        technique_ids = technique_ids_from_tags(raw.get("tags", []))
        assert technique_ids, f"{path.name} carries no attack.t* tag"
        for technique in resolve(technique_ids, techniques):
            assert technique.url.startswith("https://attack.mitre.org/")


def test_shipped_rules_load_through_detector() -> None:
    for path in _rule_files():
        assert load_rule_file(path).title
