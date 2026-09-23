"""Declarative PoC execution: placeholders, indicators and verdict semantics."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from custos_vulnerum.errors import PocError
from custos_vulnerum.lifecycle import LabEnvironment
from custos_vulnerum.pocs import resolve_text, run_plan
from custos_vulnerum.safety import LabTarget


def _target(lab: Any) -> LabTarget:
    port = lab.meta.compose.port
    return LabTarget(
        lab_id=lab.id,
        variant="vulnerable",
        base_url=f"http://127.0.0.1:{port}",
        host="127.0.0.1",
        port=port,
        project=lab.meta.compose.project,
    )


def test_resolve_text_substitutes_placeholders() -> None:
    mapping = {
        "base_url": "http://127.0.0.1:1",
        "token": "custos-aa",
        "canary_host": "canary",
        "canary_port": "1389",
    }
    out = resolve_text("/x?h={canary_host}:{canary_port}&t={token}", mapping)
    assert out == "/x?h=canary:1389&t=custos-aa"


def test_resolve_text_rejects_unknown_placeholders() -> None:
    with pytest.raises(PocError, match="unknown placeholder"):
        resolve_text("/x/{nope}", {"base_url": "http://127.0.0.1:1"})


def _apache_transport(vulnerable: bool) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<h1>It works!</h1>")
        if not vulnerable:
            return httpx.Response(404, text="Not Found")
        if "passwd" in path:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\n")
        return httpx.Response(200, text="uid=0(root) gid=0(root)\n")

    return httpx.MockTransport(handler)


def test_run_plan_vulnerable_apache(apache_lab: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(LabEnvironment, "logs", lambda self, service, since=None: "")
    env = LabEnvironment(apache_lab, "vulnerable")
    run = run_plan(
        apache_lab,
        env,
        _target(apache_lab),
        phase="poc",
        token="custos-test",
        transport=_apache_transport(vulnerable=True),
    )
    assert run.result == "vulnerable"
    assert run.phase == "poc"
    assert run.environment == "vulnerable"
    assert [step.name for step in run.steps] == [
        "baseline",
        "traversal-file-disclosure",
        "traversal-cgi-rce",
    ]
    proof = [step for step in run.steps if step.role == "proof"]
    assert all(step.indicators_met for step in proof)
    assert "passwd" in run.steps[1].request.url  # type: ignore[union-attr]


def test_run_plan_mitigated_yields_not_vulnerable(apache_lab: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(LabEnvironment, "logs", lambda self, service, since=None: "")
    env = LabEnvironment(apache_lab, "mitigated")
    run = run_plan(
        apache_lab,
        env,
        _target(apache_lab),
        phase="retest",
        token="custos-test",
        transport=_apache_transport(vulnerable=False),
    )
    assert run.result == "not_vulnerable"
    assert run.phase == "retest"
    assert all(not step.indicators_met for step in run.steps if step.role == "proof")


def test_run_plan_act_failure_is_error(apache_lab: Any, monkeypatch: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    monkeypatch.setattr(LabEnvironment, "logs", lambda self, service, since=None: "")
    run = run_plan(
        apache_lab,
        LabEnvironment(apache_lab, "vulnerable"),
        _target(apache_lab),
        phase="poc",
        token="custos-test",
        transport=httpx.MockTransport(handler),
    )
    assert run.result == "error"


def test_run_plan_canary_proof(log4j_lab: Any, monkeypatch: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/log":
            return httpx.Response(200, text="logged")
        return httpx.Response(200, text="log4j-2.14.1 ok")

    def fake_logs(self: LabEnvironment, service: str, since: Any = None) -> str:
        if service == "canary":
            return (
                "2026-09-23T10:00:02 CANARY connection from 172.18.0.3:1 payload=0..custos-test.."
            )
        return ""

    monkeypatch.setattr(LabEnvironment, "logs", fake_logs)
    run = run_plan(
        log4j_lab,
        LabEnvironment(log4j_lab, "vulnerable"),
        _target(log4j_lab),
        phase="poc",
        token="custos-test",
        transport=httpx.MockTransport(handler),
    )
    assert run.result == "vulnerable"
    canary_step = run.steps[-1]
    assert canary_step.type == "canary_ldap"
    assert canary_step.canary is not None and canary_step.canary.matched


def test_run_plan_canary_silent_means_not_vulnerable(log4j_lab: Any, monkeypatch: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/log":
            return httpx.Response(200, text="logged")
        return httpx.Response(200, text="log4j-2.14.1 ok")

    monkeypatch.setattr(LabEnvironment, "logs", lambda self, service, since=None: "")
    run = run_plan(
        log4j_lab,
        LabEnvironment(log4j_lab, "mitigated"),
        _target(log4j_lab),
        phase="retest",
        token="custos-test",
        transport=httpx.MockTransport(handler),
    )
    assert run.result == "not_vulnerable"
