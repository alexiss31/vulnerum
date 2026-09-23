"""MITRE ATT&CK resolution: rule tags -> technique rows.

Values in ``data/attack_techniques.json`` are transcribed from live ATT&CK pages
(see specs/001-vulnerum-core/research.md); each row keeps its source string.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path

from .errors import DetectionError
from .models import AttackTechnique

_ATTACK_TAG_PREFIX = "attack.t"


def load_techniques(path: Path | None = None) -> dict[str, AttackTechnique]:
    """The curated ATT&CK dataset, keyed by technique id (e.g. ``T1190``)."""
    if path is None:
        data_file = files("custos_vulnerum").joinpath("data/attack_techniques.json")
        raw = json.loads(data_file.read_text(encoding="utf-8"))
    else:
        if not path.is_file():
            raise DetectionError(f"ATT&CK dataset not found: {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
    techniques: dict[str, AttackTechnique] = {}
    for key, value in raw.items():
        technique = AttackTechnique.model_validate(value)
        if technique.technique_id != key:
            raise DetectionError(f"ATT&CK dataset key {key!r} != id {technique.technique_id!r}")
        techniques[key] = technique
    return techniques


def technique_ids_from_tags(tags: Iterable[str]) -> list[str]:
    """Extract ATT&CK technique ids from Sigma ``attack.*`` tags.

    ``attack.t1190`` -> ``T1190``; ``attack.t1059.004`` -> ``T1059.004``.
    """
    ids: list[str] = []
    for tag in tags:
        lowered = tag.lower()
        if not lowered.startswith(_ATTACK_TAG_PREFIX):
            continue
        suffix = lowered[len("attack.t") :]
        if not suffix or not all(ch.isalnum() or ch in "._-" for ch in suffix):
            continue
        technique = "T" + suffix.replace("_", ".")
        if technique not in ids:
            ids.append(technique)
    return ids


def resolve(
    technique_ids: Iterable[str], techniques: dict[str, AttackTechnique]
) -> list[AttackTechnique]:
    """Resolve technique ids to dataset rows; unknown ids raise (evidence honesty)."""
    resolved: list[AttackTechnique] = []
    for technique_id in technique_ids:
        if technique_id not in techniques:
            raise DetectionError(
                f"ATT&CK technique {technique_id} missing from data/attack_techniques.json"
            )
        resolved.append(techniques[technique_id])
    return resolved
