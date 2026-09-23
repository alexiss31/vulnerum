"""Exception hierarchy. Every operational failure raises a CustosError subclass."""

from __future__ import annotations


class CustosError(RuntimeError):
    """Base class for actionable operational errors (rendered by the CLI)."""


class CatalogError(CustosError):
    """A lab directory is missing, malformed or inconsistent."""


class SafetyError(CustosError):
    """The safety gate refused an action (Constitution I)."""


class LifecycleError(CustosError):
    """Docker Compose interaction failed."""


class PocError(CustosError):
    """A PoC step failed to execute (not a verdict: a broken run)."""


class EvidenceError(CustosError):
    """Evidence artifacts are missing or unreadable."""


class DetectionError(CustosError):
    """A Sigma rule is malformed or evaluation failed."""
