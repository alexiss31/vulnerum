"""Typed models: lab metadata, PoC plans, evidence runs and detection matches."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")


class StrictModel(BaseModel):
    """Base model: unknown keys are rejected everywhere."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Lab metadata (labs/<cve>/lab.yaml)
# ---------------------------------------------------------------------------


class AttackRef(StrictModel):
    """An ATT&CK technique a lab exercises, with its role in the narrative."""

    technique_id: str
    role: str

    @field_validator("technique_id")
    @classmethod
    def _valid_technique(cls, value: str) -> str:
        if not _TECHNIQUE_RE.match(value):
            raise ValueError(f"not an ATT&CK technique id: {value!r}")
        return value


class ComposeSpec(StrictModel):
    """Where the lab's Docker Compose project lives and how it is addressed."""

    file: str = "compose.yaml"
    mitigated_file: str = "compose.mitigated.yaml"
    project: str
    target_service: str
    port: int
    container_port: int

    @field_validator("project")
    @classmethod
    def _valid_project(cls, value: str) -> str:
        if not _PROJECT_RE.match(value):
            raise ValueError(f"not a valid compose project name: {value!r}")
        return value


class VerificationCheck(StrictModel):
    """A deterministic pre-PoC check executed by ``custos verify``."""

    kind: Literal["http_status", "body_contains", "server_marker"]
    value: str
    value_mitigated: str | None = None
    path: str = "/"
    description: str = ""

    def expected_value(self, mitigated: bool) -> str:
        if mitigated and self.value_mitigated is not None:
            return self.value_mitigated
        return self.value


class CanarySpec(StrictModel):
    """In-network canary service used as fixed PoC callback target."""

    service: str
    port: int


class LogSourceSpec(StrictModel):
    """The Sigma-style log source of the normalized events this lab emits."""

    category: str
    product: str
    service: str
    definition: str = ""


class HttpStep(StrictModel):
    """A fixed HTTP request. Placeholders: {base_url} {token} {canary_host} {canary_port}."""

    type: Literal["http"] = "http"
    name: str
    role: Literal["act", "proof"]
    method: Literal["GET", "POST", "PUT", "HEAD", "OPTIONS"] = "GET"
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    expect_status: list[int] = Field(default_factory=lambda: [200])
    expect_body: list[str] = Field(default_factory=list)
    expect_body_regex: list[str] = Field(default_factory=list)
    description: str = ""


class CanaryLdapStep(StrictModel):
    """Assert the lab canary service captured the run token (JNDI LDAP lookup fired)."""

    type: Literal["canary_ldap"] = "canary_ldap"
    name: str
    role: Literal["act", "proof"] = "proof"
    timeout_seconds: float = 10.0
    description: str = ""


PoCStep = Annotated[HttpStep | CanaryLdapStep, Field(discriminator="type")]


class PoCPlan(StrictModel):
    """Ordered fixed steps; at least one must declare exploitability (role=proof)."""

    steps: list[PoCStep]

    @model_validator(mode="after")
    def _needs_proof(self) -> PoCPlan:
        if not any(step.role == "proof" for step in self.steps):
            raise ValueError("a PoC plan needs at least one step with role='proof'")
        return self


class LogRule(StrictModel):
    """Selects evidence lines from a compose service's logs."""

    service: str
    contains: list[str] = Field(default_factory=list)
    max_lines: int = 20


class EvidenceConfig(StrictModel):
    log_rules: list[LogRule] = Field(default_factory=list)


class LabMeta(StrictModel):
    """Schema of ``labs/<cve>/lab.yaml`` (see contracts/lab-schema.md)."""

    id: str
    title: str
    summary: str
    cve: str
    cvss: float
    severity: Literal["low", "medium", "high", "critical"]
    vendor: str
    component: str
    affected_versions: str
    fixed_versions: str
    references: list[str]
    attack: list[AttackRef]
    compose: ComposeSpec
    canary: CanarySpec | None = None
    logsource: LogSourceSpec
    verification: list[VerificationCheck]
    poc: PoCPlan
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    detection_rules: list[str] = Field(default_factory=list)
    mitigation_notes: str = "mitigation.md"

    @field_validator("cve")
    @classmethod
    def _valid_cve(cls, value: str) -> str:
        if not _CVE_RE.match(value):
            raise ValueError(f"not a CVE identifier: {value!r}")
        return value

    @model_validator(mode="after")
    def _canary_consistency(self) -> LabMeta:
        uses_canary = any(
            isinstance(step, CanaryLdapStep) or "{canary_host}" in _step_text(step)
            for step in self.poc.steps
        )
        if uses_canary and self.canary is None:
            raise ValueError("steps use the canary but 'canary' is not defined")
        return self


def _step_text(step: PoCStep) -> str:
    if isinstance(step, HttpStep):
        return f"{step.path} {step.body or ''}"
    return ""


# ---------------------------------------------------------------------------
# Evidence runs (artifacts/<lab>/<run_id>/evidence.json)
# ---------------------------------------------------------------------------


class RequestRecord(StrictModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str = ""
    sent_at: datetime


class ResponseRecord(StrictModel):
    status: int
    body_excerpt: str = ""
    received_at: datetime


class LogExcerpt(StrictModel):
    service: str
    lines: list[str]


class CanaryObservation(StrictModel):
    checked: bool
    matched: bool
    matched_lines: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None


class StepEvidence(StrictModel):
    name: str
    type: Literal["http", "canary_ldap"]
    role: Literal["act", "proof"]
    description: str = ""
    expected: str
    indicators_met: bool
    request: RequestRecord | None = None
    response: ResponseRecord | None = None
    logs: list[LogExcerpt] = Field(default_factory=list)
    canary: CanaryObservation | None = None


class VerificationCheckResult(StrictModel):
    """Observed outcome of one ``custos verify`` check."""

    kind: Literal["safety_binding", "http_status", "body_contains", "server_marker"]
    description: str
    expected: str
    observed: str
    passed: bool


class VerificationReport(StrictModel):
    """Persisted record of a ``custos verify`` run (rendered into reports)."""

    lab_id: str
    variant: Literal["vulnerable", "mitigated"]
    checked_at: datetime
    passed: bool
    checks: list[VerificationCheckResult]


class DetectionMatch(StrictModel):
    rule_id: str
    rule_title: str
    rule_level: str
    attack_tags: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    matched_event: dict[str, Any] = Field(default_factory=dict)
    matched_identifiers: list[str] = Field(default_factory=list)


class AttackTechnique(StrictModel):
    technique_id: str
    name: str
    tactic_id: str
    tactic_name: str
    url: str
    source: str


class EvidenceRun(StrictModel):
    """Normalized record of one PoC/retest execution (contracts/evidence.schema.json)."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    lab_id: str
    cve: str
    phase: Literal["poc", "retest"]
    environment: Literal["vulnerable", "mitigated"]
    started_at: datetime
    finished_at: datetime
    token: str
    result: Literal["vulnerable", "not_vulnerable", "error"]
    steps: list[StepEvidence]
    detections: list[DetectionMatch] = Field(default_factory=list)
    attack: list[AttackTechnique] = Field(default_factory=list)

    @field_validator("run_id")
    @classmethod
    def _valid_run_id(cls, value: str) -> str:
        if not _RUN_ID_RE.match(value):
            raise ValueError(f"not a run id (YYYYMMDDTHHMMSSZ): {value!r}")
        return value
