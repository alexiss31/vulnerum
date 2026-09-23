"""Canary log parsing.

The Log4Shell lab runs a tiny LDAP canary *inside* the isolated lab network. A
successful JNDI lookup makes the vulnerable server open a TCP connection to the canary,
which logs the raw LDAP bytes. Evidence of exploitation is therefore a captured
connection carrying the per-run token — never code execution.
"""

from __future__ import annotations


def find_token_lines(log_text: str, token: str) -> list[str]:
    """Lines of canary output mentioning the run token (case-insensitive)."""
    needle = token.lower()
    return [line for line in log_text.splitlines() if needle in line.lower()]


def summarize(log_text: str, token: str) -> tuple[bool, list[str]]:
    """(matched, matching lines) for a canary log and a run token."""
    lines = find_token_lines(log_text, token)
    return bool(lines), lines
