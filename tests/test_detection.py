"""Sigma-subset matcher: selections, modifiers, wildcards, condition grammar."""

from __future__ import annotations

from typing import Any

from custos_vulnerum.detection import (
    SigmaRule,
    load_rules,
    logsource_compatible,
    match_event,
    match_events,
)


def _rule(detection: dict[str, Any], logsource: dict[str, str] | None = None) -> SigmaRule:
    return SigmaRule.from_mapping(
        path=__import__("pathlib").Path("inline.yml"),
        raw={
            "title": "inline",
            "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "logsource": logsource or {"category": "webserver"},
            "detection": detection,
        },
    )


EVENT: dict[str, Any] = {
    "http_path": "/icons/.%2e/%2e%2e/etc/passwd",
    "http_user_agent": "CustosPoC/1.0",
    "http_body": "echo;id",
    "status": 200,
    "message": '127.0.0.1 "GET /icons/.%2e/etc/passwd HTTP/1.1" 200',
    "category": "webserver",
    "product": "apache",
    "service": "httpd",
}


def test_keywords_or_match_case_insensitive() -> None:
    rule = _rule({"keywords": ["PASSWD", "nope"], "condition": "keywords"})
    assert match_event(rule, EVENT) is not None


def test_keywords_all_requires_every_value() -> None:
    rule = _rule({"kw": {"|all": ["custospoc", "echo"]}, "condition": "kw"})
    assert match_event(rule, EVENT) is not None
    rule_missing = _rule({"kw": {"|all": ["custospoc", "missing"]}, "condition": "kw"})
    assert match_event(rule_missing, EVENT) is None


def test_map_values_are_anded() -> None:
    rule = _rule({"sel": {"http_user_agent": "CustosPoC/1.0", "status": 200}, "condition": "sel"})
    assert match_event(rule, EVENT) is not None
    rule_fail = _rule(
        {"sel": {"http_user_agent": "CustosPoC/1.0", "status": 404}, "condition": "sel"}
    )
    assert match_event(rule_fail, EVENT) is None


def test_map_value_list_is_ored() -> None:
    rule = _rule({"sel": {"status": [404, 200]}, "condition": "sel"})
    assert match_event(rule, EVENT) is not None


def test_contains_startswith_endswith_re() -> None:
    assert match_event(_rule({"s": {"http_path|contains": ".%2e"}, "condition": "s"}), EVENT)
    assert match_event(_rule({"s": {"http_path|startswith": "/icons/"}, "condition": "s"}), EVENT)
    assert match_event(_rule({"s": {"http_path|endswith": "/etc/passwd"}, "condition": "s"}), EVENT)
    assert match_event(_rule({"s": {"http_path|re": r"etc/[a-z]+"}, "condition": "s"}), EVENT)


def test_regex_is_case_sensitive_by_default() -> None:
    rule = _rule({"s": {"http_user_agent|re": "CUSTOSPOC"}, "condition": "s"})
    assert match_event(rule, EVENT) is None


def test_exists_modifier() -> None:
    assert match_event(_rule({"s": {"http_body|exists": True}, "condition": "s"}), EVENT)
    assert match_event(_rule({"s": {"nope|exists": False}, "condition": "s"}), EVENT)


def test_all_modifier_requires_every_list_value() -> None:
    rule = _rule({"s": {"http_path|all": ["/icons/", "passwd"]}, "condition": "s"})
    assert match_event(rule, EVENT) is not None
    rule_fail = _rule({"s": {"http_path|all": ["/icons/", "shadow"]}, "condition": "s"})
    assert match_event(rule_fail, EVENT) is None


def test_default_wildcards_and_escapes() -> None:
    assert match_event(_rule({"s": {"http_user_agent": "custospoc*"}, "condition": "s"}), EVENT)
    assert match_event(_rule({"s": {"http_user_agent": "CustosPo?/1.0"}, "condition": "s"}), EVENT)
    literal_star = _rule({"s": {"http_user_agent": "Custos*\\*"}, "condition": "s"})
    assert match_event(literal_star, EVENT) is None


def test_list_of_maps_is_or() -> None:
    rule = _rule(
        {
            "s": [{"http_path|contains": "nope"}, {"http_user_agent": "CustosPoC/1.0"}],
            "condition": "s",
        }
    )
    assert match_event(rule, EVENT) is not None


def test_condition_and_or_not_parens() -> None:
    hit = _rule(
        {
            "a": {"http_path|contains": ".%2e"},
            "b": {"status": 404},
            "c": {"http_user_agent": "CustosPoC*"},
            "condition": "a and (b or c) and not b",
        }
    )
    assert match_event(hit, EVENT) is not None
    miss = _rule(
        {"a": {"http_path|contains": ".%2e"}, "b": {"status": 200}, "condition": "a and not b"}
    )
    assert match_event(miss, EVENT) is None


def test_condition_of_them_and_patterns() -> None:
    one_of_them = _rule(
        {"a": {"status": 404}, "b": {"http_user_agent": "CustosPoC*"}, "condition": "1 of them"}
    )
    assert match_event(one_of_them, EVENT) is not None
    all_of_pattern = _rule(
        {
            "sel_x": {"status": 200},
            "sel_y": {"http_path|contains": "passwd"},
            "other": {"http_body|contains": "nope"},
            "condition": "all of sel_*",
        }
    )
    assert match_event(all_of_pattern, EVENT) is not None
    underscore_excluded = _rule(
        {"_hidden": {"http_path|contains": "passwd"}, "condition": "all of them"}
    )
    assert match_event(underscore_excluded, EVENT) is None


def test_condition_list_is_disjunction() -> None:
    rule = _rule({"a": {"status": 404}, "b": {"status": 200}, "condition": ["a", "b"]})
    assert match_event(rule, EVENT) is not None


def test_logsource_compatibility_gates_matching() -> None:
    rule = _rule(
        {"s": {"http_path|contains": "passwd"}, "condition": "s"},
        logsource={"category": "webserver", "product": "nginx", "service": "http"},
    )
    assert not logsource_compatible(rule, EVENT)
    assert match_event(rule, EVENT) is None
    assert match_events([rule], [EVENT]) == []


def test_shipped_rules_load() -> None:
    from custos_vulnerum.config import Paths

    rules = load_rules(Paths.resolve().sigma)
    assert len(rules) == 3
    assert all(rule.detection.get("condition") for rule in rules)
