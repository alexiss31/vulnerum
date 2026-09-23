"""Path resolution for labs, detection content and generated artifacts."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_ENV_ROOT = "CUSTOS_ROOT"
_ENV_ARTIFACTS = "CUSTOS_ARTIFACTS_DIR"


def find_repo_root(start: Path | None = None) -> Path:
    """Locate the repository root (the directory holding ``labs/`` and ``detection/``).

    Resolution order: ``$CUSTOS_ROOT`` (validated), then walking parents of ``start``
    (default: current working directory).
    """
    env_root = os.environ.get(_ENV_ROOT)
    if env_root:
        root = Path(env_root).expanduser().resolve()
        if not (root / "labs").is_dir():
            raise FileNotFoundError(f"{_ENV_ROOT}={root} does not contain a labs/ directory")
        return root
    cursor = (start or Path.cwd()).resolve()
    for candidate in (cursor, *cursor.parents):
        if (candidate / "labs").is_dir() and (candidate / "detection").is_dir():
            return candidate
    raise FileNotFoundError(
        "Could not locate the repository root (no labs/ + detection/ found). "
        f"Run from the checkout or set {_ENV_ROOT}."
    )


@dataclass(frozen=True)
class Paths:
    """All filesystem locations the tool reads from or writes to."""

    root: Path
    labs: Path
    detection: Path
    sigma: Path
    wazuh: Path
    artifacts: Path

    @classmethod
    def resolve(cls, root: Path | None = None) -> Paths:
        base = (root or find_repo_root()).resolve()
        artifacts_env = os.environ.get(_ENV_ARTIFACTS)
        artifacts = (
            Path(artifacts_env).expanduser().resolve() if artifacts_env else base / "artifacts"
        )
        detection = base / "detection"
        return cls(
            root=base,
            labs=base / "labs",
            detection=detection,
            sigma=detection / "sigma",
            wazuh=detection / "wazuh",
            artifacts=artifacts,
        )
