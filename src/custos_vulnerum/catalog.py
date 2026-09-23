"""Lab discovery and loading (labs/<cve>/lab.yaml)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from .config import Paths
from .errors import CatalogError
from .models import LabMeta

LAB_FILE = "lab.yaml"


@dataclass(frozen=True)
class LoadedLab:
    """A lab directory bound to its validated metadata."""

    meta: LabMeta
    directory: Path

    @property
    def id(self) -> str:
        return self.meta.id

    def compose_file(self, mitigated: bool) -> Path:
        name = self.meta.compose.mitigated_file if mitigated else self.meta.compose.file
        path = self.directory / name
        return path

    def mitigation_path(self) -> Path:
        return self.directory / self.meta.mitigation_notes


def load_lab(directory: Path) -> LoadedLab:
    """Load and validate ``lab.yaml``; the lab id must equal its directory name."""
    lab_file = directory / LAB_FILE
    if not lab_file.is_file():
        raise CatalogError(f"{directory} has no {LAB_FILE}")
    try:
        raw = yaml.safe_load(lab_file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CatalogError(f"{lab_file}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise CatalogError(f"{lab_file}: expected a mapping at the top level")
    try:
        meta = LabMeta.model_validate(raw)
    except ValidationError as exc:
        raise CatalogError(f"{lab_file}: {exc}") from exc
    if meta.id != directory.name:
        raise CatalogError(f"{lab_file}: id {meta.id!r} != directory name {directory.name!r}")
    mitigated_file = directory / meta.compose.mitigated_file
    if not (directory / meta.compose.file).is_file():
        raise CatalogError(f"{lab_file}: compose file {meta.compose.file!r} is missing")
    if not mitigated_file.is_file():
        raise CatalogError(
            f"{lab_file}: mitigated compose file {meta.compose.mitigated_file!r} is missing"
        )
    if not (directory / meta.mitigation_notes).is_file():
        raise CatalogError(f"{lab_file}: mitigation notes {meta.mitigation_notes!r} are missing")
    return LoadedLab(meta=meta, directory=directory)


def discover_labs(paths: Paths) -> list[LoadedLab]:
    """All labs in ``labs/`` sorted by id. Underscore-prefixed dirs (templates) are skipped."""
    if not paths.labs.is_dir():
        raise CatalogError(f"labs directory not found: {paths.labs}")
    labs: list[LoadedLab] = []
    for entry in sorted(paths.labs.iterdir()):
        if not entry.is_dir() or entry.name.startswith((".", "_")):
            continue
        if not (entry / LAB_FILE).is_file():
            continue
        labs.append(load_lab(entry))
    return labs


def get_lab(paths: Paths, lab_id: str) -> LoadedLab:
    """Load one lab by id with a helpful error listing known ids."""
    directory = paths.labs / lab_id
    if (directory / LAB_FILE).is_file():
        return load_lab(directory)
    known = ", ".join(lab.id for lab in discover_labs(paths)) or "(none)"
    raise CatalogError(f"unknown lab {lab_id!r}; known labs: {known}")
