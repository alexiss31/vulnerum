"""Deterministic pre-PoC verification checks (``custos verify``)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from .catalog import LoadedLab
from .lifecycle import LabEnvironment
from .models import VerificationCheckResult, VerificationReport
from .safety import assert_managed


def run_verification(
    lab: LoadedLab,
    env: LabEnvironment,
    transport: httpx.BaseTransport | None = None,
) -> VerificationReport:
    """Run the lab's declared checks plus the safety re-verification, and record observed values."""
    results: list[VerificationCheckResult] = []

    containers = assert_managed(env)
    results.append(
        VerificationCheckResult(
            kind="safety_binding",
            description="managed containers + loopback-only bindings",
            expected="io.custos labels present, all published ports bound to 127.0.0.1",
            observed=f"{len(containers)} managed container(s) in project {env.project!r}",
            passed=True,
        )
    )

    with httpx.Client(timeout=10.0, trust_env=False, transport=transport) as client:
        responses: dict[str, httpx.Response] = {}
        for check in lab.meta.verification:
            expected = check.expected_value(env.mitigated)
            if check.path not in responses:
                responses[check.path] = client.get(f"{env.base_url}{check.path}")
            response = responses[check.path]
            if check.kind == "http_status":
                observed = str(response.status_code)
                passed = observed == expected
            elif check.kind == "body_contains":
                present = expected in response.text
                observed = "present" if present else "absent"
                passed = present
            else:  # server_marker
                observed = response.headers.get("server", "(no Server header)")
                passed = expected in observed
            results.append(
                VerificationCheckResult(
                    kind=check.kind,
                    description=check.description or f"{check.kind} == {expected}",
                    expected=expected,
                    observed=observed,
                    passed=passed,
                )
            )

    return VerificationReport(
        lab_id=lab.id,
        variant=env.variant,
        checked_at=datetime.now(UTC),
        passed=all(item.passed for item in results),
        checks=results,
    )
