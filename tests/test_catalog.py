"""Lab discovery and loading (labs/ is data — see labs/README.md)."""

from __future__ import annotations

from pathlib import Path

import pytest

from custos_vulnerum.catalog import discover_labs, get_lab, load_lab
from custos_vulnerum.config import Paths
from custos_vulnerum.errors import CatalogError


def test_discovery_finds_shipped_labs_and_skips_template(repo_paths: Paths) -> None:
    labs = discover_labs(repo_paths)
    ids = [lab.id for lab in labs]
    assert ids == ["cve-2021-41773", "cve-2021-44228"]
    assert "_template" not in ids


def test_get_lab_unknown_lists_known(repo_paths: Paths) -> None:
    with pytest.raises(CatalogError, match="cve-2021-41773"):
        get_lab(repo_paths, "cve-1999-9999")


def test_load_lab_rejects_id_mismatch(repo_paths: Paths, tmp_path: Path) -> None:
    import shutil

    src = repo_paths.labs / "cve-2021-41773"
    dst = tmp_path / "cve-2021-41773"
    shutil.copytree(src, dst)
    lab_file = dst / "lab.yaml"
    lab_file.write_text(
        lab_file.read_text(encoding="utf-8").replace("id: cve-2021-41773", "id: cve-2021-9999"),
        encoding="utf-8",
    )
    with pytest.raises(CatalogError, match="directory name"):
        load_lab(dst)


def test_load_lab_requires_compose_files(repo_paths: Paths, tmp_path: Path) -> None:
    import shutil

    dst = tmp_path / "cve-2021-41773"
    shutil.copytree(repo_paths.labs / "cve-2021-41773", dst)
    (dst / "compose.mitigated.yaml").unlink()
    with pytest.raises(CatalogError, match="mitigated compose file"):
        load_lab(dst)


def test_template_lab_is_loadable_when_copied(repo_paths: Paths, tmp_path: Path) -> None:
    """SC-005: a new lab is data only — the template loads after copy + rename."""
    import shutil

    src = repo_paths.labs / "_template"
    dst = tmp_path / "cve-0000-0000"
    shutil.copytree(src, dst)
    lab_file = dst / "lab.yaml"
    lab_file.write_text(
        lab_file.read_text(encoding="utf-8").replace("id: cve-0000-0000", "id: cve-0000-0000"),
        encoding="utf-8",
    )
    lab = load_lab(dst)
    assert lab.meta.cve == "CVE-0000-0000"
    assert any(step.role == "proof" for step in lab.meta.poc.steps)
