"""Compose lifecycle plumbing (pure parsing/planning — no Docker calls)."""

from __future__ import annotations

from typing import Any

from custos_vulnerum.lifecycle import LabEnvironment


def test_project_and_variant_naming(apache_lab: Any) -> None:
    vulnerable = LabEnvironment(apache_lab, "vulnerable")
    mitigated = LabEnvironment(apache_lab, "mitigated")
    assert vulnerable.project == "custos-cve-2021-41773"
    assert mitigated.project == "custos-cve-2021-41773-mit"
    assert vulnerable.compose_file.name == "compose.yaml"
    assert mitigated.compose_file.name == "compose.mitigated.yaml"
    assert vulnerable.base_url == "http://127.0.0.1:8917"
    assert vulnerable.mitigated is False
    assert mitigated.mitigated is True


def test_to_container_info_parses_docker_inspect() -> None:
    inspect_item: dict[str, object] = {
        "Id": "abcdef1234567890",
        "Name": "/custos-cve-2021-41773-httpd-1",
        "Config": {
            "Labels": {
                "com.docker.compose.service": "httpd",
                "io.custos.project": "vulnerum",
                "io.custos.lab": "cve-2021-41773",
            }
        },
        "HostConfig": {
            "PortBindings": {
                "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8917"}],
            }
        },
    }
    info = LabEnvironment._to_container_info(inspect_item)
    assert info.id == "abcdef123456"
    assert info.name == "custos-cve-2021-41773-httpd-1"
    assert info.service == "httpd"
    assert info.labels["io.custos.lab"] == "cve-2021-41773"
    assert len(info.bindings) == 1
    assert info.bindings[0].host_ip == "127.0.0.1"
    assert info.bindings[0].host_port == "8917"
