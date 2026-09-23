"""Canary log parsing."""

from __future__ import annotations

from custos_vulnerum.canary import find_token_lines, summarize


def test_find_token_lines_case_insensitive() -> None:
    log = "CANARY listening\nx CANARY connection payload=0..CUSTOS-AbC123.."
    assert find_token_lines(log, "custos-abc123") == [
        "x CANARY connection payload=0..CUSTOS-AbC123.."
    ]
    assert find_token_lines(log, "custos-zzz") == []


def test_summarize() -> None:
    matched, lines = summarize("CANARY connection from 10.0.0.2 tok=abc", "abc")
    assert matched and len(lines) == 1
    matched, lines = summarize("silent", "abc")
    assert not matched and lines == []
