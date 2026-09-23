"""Constitution I: the safety gate (loopback-only, managed containers only)."""

from __future__ import annotations

from typing import Any

import pytest

from custos_vulnerum import safety
from custos_vulnerum.errors import SafetyError
from custos_vulnerum.lifecycle import ContainerInfo, LabEnvironment, PortBinding


def _container(
    labels: dict[str, str] | None = None,
    bindings: tuple[PortBinding, ...] = (),
) -> ContainerInfo:
    return ContainerInfo(
        id="abc123def456",
        name="lab-httpd-1",
        service="httpd",
        labels=labels or {},
        bindings=bindings,
    )


def _managed(apache_lab: Any) -> dict[str, str]:
    return {
        safety.MANAGED_LABEL_PROJECT: safety.MANAGED_PROJECT_VALUE,
        safety.MANAGED_LABEL_LAB: apache_lab.id,
    }


def test_loopback_gate_rejects_remote_hosts() -> None:
    with pytest.raises(SafetyError, match="non-loopback"):
        safety.assert_loopback_url("http://203.0.113.5:8917/")
    with pytest.raises(SafetyError, match="non-loopback"):
        safety.assert_loopback_url("http://evil.example.com/")


def test_loopback_gate_rejects_non_http() -> None:
    with pytest.raises(SafetyError, match="scheme"):
        safety.assert_loopback_url("ftp://127.0.0.1/x")


def test_loopback_gate_accepts_loopback() -> None:
    safety.assert_loopback_url("http://127.0.0.1:8917/")
    safety.assert_loopback_url("http://localhost:8917/")


def test_managed_gate_accepts_our_containers(apache_lab: Any, monkeypatch: Any) -> None:
    env = LabEnvironment(apache_lab, "vulnerable")
    container = _container(
        labels=_managed(apache_lab),
        bindings=(PortBinding("80/tcp", "127.0.0.1", "8917"),),
    )
    monkeypatch.setattr(LabEnvironment, "containers", lambda self: [container])
    assert safety.assert_managed(env) == [container]


def test_managed_gate_rejects_unlabelled_containers(apache_lab: Any, monkeypatch: Any) -> None:
    env = LabEnvironment(apache_lab, "vulnerable")
    monkeypatch.setattr(
        LabEnvironment,
        "containers",
        lambda self: [_container(bindings=(PortBinding("80/tcp", "127.0.0.1", "8917"),))],
    )
    with pytest.raises(SafetyError, match="not a Custos Vulnerum container"):
        safety.assert_managed(env)


def test_managed_gate_rejects_non_loopback_binding(apache_lab: Any, monkeypatch: Any) -> None:
    env = LabEnvironment(apache_lab, "vulnerable")
    monkeypatch.setattr(
        LabEnvironment,
        "containers",
        lambda self: [
            _container(
                labels=_managed(apache_lab),
                bindings=(PortBinding("80/tcp", "0.0.0.0", "8917"),),
            )
        ],
    )
    with pytest.raises(SafetyError, match="not loopback-only"):
        safety.assert_managed(env)


def test_managed_gate_requires_expected_port(apache_lab: Any, monkeypatch: Any) -> None:
    env = LabEnvironment(apache_lab, "vulnerable")
    monkeypatch.setattr(
        LabEnvironment,
        "containers",
        lambda self: [
            _container(
                labels=_managed(apache_lab),
                bindings=(PortBinding("80/tcp", "127.0.0.1", "9999"),),
            )
        ],
    )
    with pytest.raises(SafetyError, match="8917 is not published"):
        safety.assert_managed(env)


def test_managed_gate_requires_running_lab(apache_lab: Any, monkeypatch: Any) -> None:
    env = LabEnvironment(apache_lab, "vulnerable")
    monkeypatch.setattr(LabEnvironment, "containers", lambda self: [])
    with pytest.raises(SafetyError, match="is not running"):
        safety.assert_managed(env)


def test_resolve_target_is_loopback_after_gate(apache_lab: Any, monkeypatch: Any) -> None:
    env = LabEnvironment(apache_lab, "vulnerable")
    monkeypatch.setattr(
        LabEnvironment,
        "containers",
        lambda self: [
            _container(
                labels=_managed(apache_lab),
                bindings=(PortBinding("80/tcp", "127.0.0.1", "8917"),),
            )
        ],
    )
    target = safety.resolve_target(env)
    assert target.host == "127.0.0.1"
    assert target.base_url == "http://127.0.0.1:8917"
    assert target.project == "custos-cve-2021-41773"
