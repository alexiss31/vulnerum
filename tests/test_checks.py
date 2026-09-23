"""Verification checks with a mocked transport (no Docker, no network)."""

from __future__ import annotations

from typing import Any

import httpx

from custos_vulnerum.checks import run_verification
from custos_vulnerum.lifecycle import ContainerInfo, LabEnvironment, PortBinding


def _stub_containers(monkeypatch: Any, lab: Any) -> None:
    container = ContainerInfo(
        id="abc123",
        name="lab-httpd-1",
        service="httpd",
        labels={"io.custos.project": "vulnerum", "io.custos.lab": lab.id},
        bindings=(PortBinding("80/tcp", "127.0.0.1", str(lab.meta.compose.port)),),
    )
    monkeypatch.setattr(LabEnvironment, "containers", lambda self: [container])


def test_verification_passes_on_vulnerable_apache(apache_lab: Any, monkeypatch: Any) -> None:
    _stub_containers(monkeypatch, apache_lab)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="<h1>It works!</h1>", headers={"server": "Apache/2.4.49 (Unix)"}
        )

    report = run_verification(
        apache_lab,
        LabEnvironment(apache_lab, "vulnerable"),
        transport=httpx.MockTransport(handler),
    )
    assert report.passed
    kinds = [check.kind for check in report.checks]
    assert kinds == ["safety_binding", "http_status", "server_marker"]
    server_check = report.checks[-1]
    assert server_check.expected == "2.4.49"
    assert "2.4.49" in server_check.observed


def test_verification_uses_mitigated_expectation(apache_lab: Any, monkeypatch: Any) -> None:
    _stub_containers(monkeypatch, apache_lab)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="<h1>It works!</h1>", headers={"server": "Apache/2.4.51 (Unix)"}
        )

    report = run_verification(
        apache_lab,
        LabEnvironment(apache_lab, "mitigated"),
        transport=httpx.MockTransport(handler),
    )
    assert report.passed
    assert report.checks[-1].expected == "2.4.51"


def test_verification_fails_on_wrong_marker(apache_lab: Any, monkeypatch: Any) -> None:
    _stub_containers(monkeypatch, apache_lab)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="<h1>It works!</h1>", headers={"server": "Apache/2.4.62 (Unix)"}
        )

    report = run_verification(
        apache_lab,
        LabEnvironment(apache_lab, "vulnerable"),
        transport=httpx.MockTransport(handler),
    )
    assert not report.passed
    assert not report.checks[-1].passed


def test_verification_body_contains(log4j_lab: Any, monkeypatch: Any) -> None:
    _stub_containers(monkeypatch, log4j_lab)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="log4j-2.14.1 ok")

    report = run_verification(
        log4j_lab,
        LabEnvironment(log4j_lab, "vulnerable"),
        transport=httpx.MockTransport(handler),
    )
    assert report.passed
    body_checks = [c for c in report.checks if c.kind == "body_contains"]
    assert body_checks and body_checks[0].observed == "present"


def test_verification_body_contains_absent_fails(log4j_lab: Any, monkeypatch: Any) -> None:
    _stub_containers(monkeypatch, log4j_lab)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="log4j-2.17.1 ok")

    report = run_verification(
        log4j_lab,
        LabEnvironment(log4j_lab, "vulnerable"),
        transport=httpx.MockTransport(handler),
    )
    assert not report.passed
