"""Declarative PoC plan execution (fixed payloads only — Constitution I/II).

Steps come from ``lab.yaml``; the runner only knows two step types:

- ``http``: one fixed request; its declared expectations are the indicators;
- ``canary_ldap``: the run token observed in the lab canary service's logs.

Verdict semantics: a step's indicators being met means *exploitable*. ``role: act``
steps must succeed or the run is ``error``; ``role: proof`` steps drive the verdict:
``vulnerable`` iff any proof step's indicators are met.
"""

from __future__ import annotations

import re
import secrets
import time
from datetime import UTC, datetime
from typing import Literal

import httpx

from .canary import summarize as canary_summarize
from .catalog import LoadedLab
from .errors import PocError, SafetyError
from .lifecycle import LabEnvironment
from .models import (
    CanaryLdapStep,
    CanaryObservation,
    EvidenceRun,
    HttpStep,
    LogExcerpt,
    RequestRecord,
    ResponseRecord,
    StepEvidence,
)
from .safety import LabTarget, assert_loopback_url

_BODY_EXCERPT_LIMIT = 2000
_REQUEST_TIMEOUT = 15.0
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_LOG_POLL_INTERVAL = 0.5


def new_token() -> str:
    """Per-run canary token (recorded in evidence)."""
    return f"custos-{secrets.token_hex(6)}"


def resolve_text(text: str, mapping: dict[str, str]) -> str:
    """Substitute ``{base_url} {token} {canary_host} {canary_port}`` placeholders."""

    def _sub(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in mapping:
            raise PocError(f"unknown placeholder {{{key}}} in {text!r}")
        return mapping[key]

    resolved = _PLACEHOLDER_RE.sub(_sub, text)
    leftovers = [m.group(1) for m in _PLACEHOLDER_RE.finditer(resolved)]
    if leftovers:
        raise PocError(f"unresolved placeholders {leftovers} in {text!r}")
    return resolved


def _expectation_text(step: HttpStep) -> str:
    parts = [f"status in {step.expect_status}"]
    if step.expect_body:
        parts.append(f"body contains {step.expect_body}")
    if step.expect_body_regex:
        parts.append(f"body matches {step.expect_body_regex}")
    return " and ".join(parts)


def _http_indicators(step: HttpStep, response: httpx.Response) -> bool:
    body = response.text
    if response.status_code not in step.expect_status:
        return False
    if any(needle not in body for needle in step.expect_body):
        return False
    return all(re.search(pattern, body) is not None for pattern in step.expect_body_regex)


def _excerpt(text: str) -> str:
    return text[:_BODY_EXCERPT_LIMIT]


def _select_logs(env: LabEnvironment, lab: LoadedLab, since: datetime) -> list[LogExcerpt]:
    excerpts: list[LogExcerpt] = []
    for rule in lab.meta.evidence.log_rules:
        raw = env.logs(rule.service, since=since)
        lines = raw.splitlines()
        if rule.contains:
            needles = [word.lower() for word in rule.contains]
            lines = [line for line in lines if any(needle in line.lower() for needle in needles)]
        excerpts.append(LogExcerpt(service=rule.service, lines=lines[: rule.max_lines]))
    return excerpts


def run_plan(
    lab: LoadedLab,
    env: LabEnvironment,
    target: LabTarget,
    phase: str,
    token: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> EvidenceRun:
    """Execute the lab's fixed PoC plan and return the normalized evidence run."""
    run_token = token or new_token()
    started = datetime.now(UTC)
    mapping = {
        "base_url": target.base_url,
        "token": run_token,
        "canary_host": lab.meta.canary.service if lab.meta.canary else "",
        "canary_port": str(lab.meta.canary.port) if lab.meta.canary else "",
    }
    step_evidence: list[StepEvidence] = []
    run_error = False

    with httpx.Client(
        timeout=_REQUEST_TIMEOUT, trust_env=False, follow_redirects=False, transport=transport
    ) as client:
        for step in lab.meta.poc.steps:
            if isinstance(step, HttpStep):
                evidence, failed = _run_http_step(step, client, mapping, env, lab)
            elif isinstance(step, CanaryLdapStep):
                evidence, failed = _run_canary_step(step, env, lab, run_token, started)
            else:  # pragma: no cover - discriminated union is exhaustive
                raise PocError(f"unsupported step type: {step!r}")
            step_evidence.append(evidence)
            run_error = run_error or failed

    proof_met = any(ev.role == "proof" and ev.indicators_met for ev in step_evidence)
    result: Literal["vulnerable", "not_vulnerable", "error"]
    if run_error:
        result = "error"
    elif proof_met:
        result = "vulnerable"
    else:
        result = "not_vulnerable"
    return EvidenceRun(
        run_id=started.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ"),
        lab_id=lab.id,
        cve=lab.meta.cve,
        phase="poc" if phase == "poc" else "retest",
        environment=env.variant,
        started_at=started,
        finished_at=datetime.now(UTC),
        token=run_token,
        result=result,
        steps=step_evidence,
    )


def _run_http_step(
    step: HttpStep,
    client: httpx.Client,
    mapping: dict[str, str],
    env: LabEnvironment,
    lab: LoadedLab,
) -> tuple[StepEvidence, bool]:
    url = f"{target_base(mapping)}{resolve_text(step.path, mapping)}"
    assert_loopback_url(url)
    body = resolve_text(step.body, mapping) if step.body else None
    headers = {k: resolve_text(v, mapping) for k, v in step.headers.items()}
    window_start = datetime.now(UTC)
    sent_at = window_start
    try:
        request = client.build_request(step.method, url, headers=headers, content=body)
        sent_at = datetime.now(UTC)
        response = client.send(request)
        received_at = datetime.now(UTC)
    except httpx.HTTPError as exc:
        raise PocError(f"step {step.name!r}: request to {url} failed: {exc}") from exc

    indicators_met = _http_indicators(step, response)
    failed = step.role == "act" and not indicators_met
    request_record = RequestRecord(
        method=step.method,
        url=url,
        headers={k: str(v) for k, v in request.headers.items()},
        body_excerpt=_excerpt(body or ""),
        sent_at=sent_at,
    )
    response_record = ResponseRecord(
        status=response.status_code,
        body_excerpt=_excerpt(response.text),
        received_at=received_at,
    )
    evidence = StepEvidence(
        name=step.name,
        type="http",
        role=step.role,
        description=step.description,
        expected=_expectation_text(step),
        indicators_met=indicators_met,
        request=request_record,
        response=response_record,
        logs=_select_logs(env, lab, since=window_start),
    )
    return evidence, failed


def _run_canary_step(
    step: CanaryLdapStep,
    env: LabEnvironment,
    lab: LoadedLab,
    token: str,
    run_started: datetime,
) -> tuple[StepEvidence, bool]:
    if lab.meta.canary is None:
        raise PocError(f"step {step.name!r}: lab defines no canary service")
    service = lab.meta.canary.service
    deadline = time.monotonic() + step.timeout_seconds
    matched: bool = False
    lines: list[str] = []
    observed_at: datetime | None = None
    while time.monotonic() < deadline:
        matched, lines = canary_summarize(env.logs(service, since=run_started), token)
        if matched:
            observed_at = datetime.now(UTC)
            break
        time.sleep(_LOG_POLL_INTERVAL)
    indicators_met = matched
    failed = step.role == "act" and not indicators_met
    evidence = StepEvidence(
        name=step.name,
        type="canary_ldap",
        role=step.role,
        description=step.description,
        expected=f"canary service {service!r} captured the run token (JNDI LDAP lookup)",
        indicators_met=indicators_met,
        logs=[LogExcerpt(service=service, lines=lines[:20])],
        canary=CanaryObservation(
            checked=True, matched=matched, matched_lines=lines[:20], observed_at=observed_at
        ),
    )
    return evidence, failed


def target_base(mapping: dict[str, str]) -> str:
    base = mapping.get("base_url", "")
    if not base:
        raise SafetyError("no base_url in placeholder mapping")
    return base
