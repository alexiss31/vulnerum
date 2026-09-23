"""Sigma-subset rule matching over normalized evidence events.

Rules are portable Sigma v2 (validated in CI with current SigmaHQ tooling). This module
implements the deterministic subset the offline detector needs:

- search identifiers: keyword lists (OR), ``'|all'`` keyword lists (AND), maps of
  ``field: value`` (AND) with value lists (OR), lists of maps (OR);
- value modifiers: ``|contains``, ``|startswith``, ``|endswith``, ``|re``,
  ``|exists``, ``|all``;
- wildcards ``*`` and ``?`` in plain values (case-insensitive, ``\\`` escapes);
- conditions: ``and`` / ``or`` / ``not``, parentheses, ``N of them``, ``all of them``,
  ``N of pattern*``, ``all of pattern*``.

Semantics follow the Sigma rules specification v2.1.0 where applicable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import DetectionError

_CONDITION_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INT_RE = re.compile(r"^\d+$")

Event = dict[str, Any]


@dataclass(frozen=True)
class SigmaRule:
    """A parsed Sigma rule (metadata kept for reporting)."""

    path: Path
    rule_id: str
    title: str
    level: str
    status: str
    tags: tuple[str, ...]
    logsource: dict[str, str]
    detection: dict[str, Any]

    @classmethod
    def from_mapping(cls, path: Path, raw: dict[str, Any]) -> SigmaRule:
        detection = raw.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise DetectionError(f"{path}: rule has no detection.condition")
        logsource_raw = raw.get("logsource") or {}
        if not isinstance(logsource_raw, dict):
            raise DetectionError(f"{path}: logsource must be a mapping")
        logsource = {k: str(v) for k, v in logsource_raw.items() if k != "definition"}
        tags = tuple(str(tag) for tag in raw.get("tags", []) or [])
        return cls(
            path=path,
            rule_id=str(raw.get("id", path.stem)),
            title=str(raw.get("title", path.stem)),
            level=str(raw.get("level", "medium")),
            status=str(raw.get("status", "experimental")),
            tags=tags,
            logsource=logsource,
            detection=detection,
        )


@dataclass(frozen=True)
class MatchResult:
    """One rule hit on one event."""

    rule: SigmaRule
    event: Event
    matched_identifiers: tuple[str, ...]


def load_rule_file(path: Path) -> SigmaRule:
    """Load and parse a single Sigma rule file."""
    if not path.is_file():
        raise DetectionError(f"Sigma rule not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise DetectionError(f"{path}: rule must be a mapping")
    return SigmaRule.from_mapping(path, raw)


def load_rules(directory: Path) -> list[SigmaRule]:
    """Load every ``*.yml``/``*.yaml`` rule from a directory (sorted by filename)."""
    if not directory.is_dir():
        raise DetectionError(f"Sigma rule directory not found: {directory}")
    return [
        load_rule_file(path)
        for path in sorted(directory.iterdir())
        if path.suffix in {".yml", ".yaml"}
    ]


def logsource_compatible(rule: SigmaRule, event: Event) -> bool:
    """A rule applies when every declared logsource key appears on the event."""
    return all(event.get(key) == value for key, value in rule.logsource.items())


def match_event(rule: SigmaRule, event: Event) -> MatchResult | None:
    """Evaluate one rule against one event; None when it does not apply or match."""
    if not logsource_compatible(rule, event):
        return None
    matched_ids = {
        name
        for name, definition in rule.detection.items()
        if name != "condition" and _eval_identifier(definition, event)
    }
    condition = rule.detection["condition"]
    conditions = condition if isinstance(condition, list) else [condition]
    for single in conditions:
        expr = _parse_condition(str(single))
        hit_ids = _eval_condition(expr, matched_ids, set(rule.detection) - {"condition"})
        if hit_ids is not None:
            return MatchResult(
                rule=rule,
                event=event,
                matched_identifiers=tuple(sorted(hit_ids)),
            )
    return None


def match_events(rules: list[SigmaRule], events: list[Event]) -> list[MatchResult]:
    """All rule hits for a list of events, in rule-then-event order."""
    results: list[MatchResult] = []
    for rule in rules:
        for event in events:
            result = match_event(rule, event)
            if result is not None:
                results.append(result)
    return results


# ---------------------------------------------------------------------------
# Selection (search-identifier) evaluation
# ---------------------------------------------------------------------------


def _event_text(event: Event) -> str:
    return " ".join(str(value) for value in event.values())


def _eval_identifier(definition: Any, event: Event) -> bool:
    if isinstance(definition, list):
        if all(isinstance(item, dict) for item in definition):
            return any(_eval_map(item, event) for item in definition)
        return any(_keyword_match(str(item), _event_text(event)) for item in definition)
    if isinstance(definition, dict):
        return _eval_map(definition, event)
    return _keyword_match(str(definition), _event_text(event))


def _eval_map(definition: dict[str, Any], event: Event) -> bool:
    for raw_key, raw_value in definition.items():
        if raw_key == "|all":
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            if not all(_keyword_match(str(value), _event_text(event)) for value in values):
                return False
            continue
        key_parts = str(raw_key).split("|")
        field_name, mods = key_parts[0], key_parts[1:]
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        if "exists" in mods:
            wanted = str(raw_value).lower() == "true"
            if (field_name in event) != wanted:
                return False
            continue
        if "all" in mods:
            if not all(_match_field(event.get(field_name), value, mods) for value in values):
                return False
            continue
        if not any(_match_field(event.get(field_name), value, mods) for value in values):
            return False
    return True


def _match_field(field_value: Any, spec: Any, mods: list[str]) -> bool:
    if field_value is None:
        return False
    text = str(field_value)
    if "re" in mods:
        try:
            return re.search(str(spec), text) is not None
        except re.error as exc:
            raise DetectionError(f"invalid regex {spec!r}: {exc}") from exc
    needle = str(spec)
    lowered_text = text.lower()
    if "contains" in mods:
        return _unescape(needle).lower() in lowered_text
    if "startswith" in mods:
        return lowered_text.startswith(_unescape(needle).lower())
    if "endswith" in mods:
        return lowered_text.endswith(_unescape(needle).lower())
    return _wildcard_match(needle, text)


def _keyword_match(needle: str, haystack: str) -> bool:
    return needle.lower() in haystack.lower()


def _unescape(value: str) -> str:
    return value.replace("\\*", "*").replace("\\?", "?").replace("\\\\", "\\")


def _wildcard_match(pattern: str, text: str) -> bool:
    """Case-insensitive glob with ``*``/``?`` and ``\\`` escapes (Sigma semantics)."""
    regex = _glob_to_regex(pattern)
    return re.search(regex, text, re.IGNORECASE | re.DOTALL) is not None


def _glob_to_regex(pattern: str) -> str:
    out: list[str] = ["(?s)"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            out.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        index += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Condition parsing/evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Ident:
    name: str


@dataclass(frozen=True)
class _Not:
    expr: Any


@dataclass(frozen=True)
class _And:
    left: Any
    right: Any


@dataclass(frozen=True)
class _Or:
    left: Any
    right: Any


@dataclass(frozen=True)
class _Of:
    count: int | None  # None == all
    pattern: str | None  # None == them


@dataclass
class _Parser:
    tokens: list[str]
    pos: int = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token


def _parse_condition(text: str) -> Any:
    tokens = [match.group(1) for match in _CONDITION_TOKEN_RE.finditer(text)]
    if not tokens:
        raise DetectionError(f"empty condition: {text!r}")
    parser = _Parser(tokens)
    expr = _parse_or(parser)
    if parser.peek() is not None:
        raise DetectionError(f"unexpected token {parser.peek()!r} in condition {text!r}")
    return expr


def _parse_or(parser: _Parser) -> Any:
    left = _parse_and(parser)
    while True:
        token = parser.peek()
        if token is None or token.lower() != "or":
            break
        parser.take()
        left = _Or(left, _parse_and(parser))
    return left


def _parse_and(parser: _Parser) -> Any:
    left = _parse_not(parser)
    while True:
        token = parser.peek()
        if token is None or token.lower() != "and":
            break
        parser.take()
        left = _And(left, _parse_not(parser))
    return left


def _parse_not(parser: _Parser) -> Any:
    token = parser.peek()
    if token is not None and token.lower() == "not":
        parser.take()
        return _Not(_parse_not(parser))
    return _parse_atom(parser)


def _parse_atom(parser: _Parser) -> Any:
    token = parser.take()
    lowered = token.lower()
    if token == "(":  # condition grammar token, not a credential  # nosec B105
        expr = _parse_or(parser)
        closing = parser.peek()
        if closing != ")":
            raise DetectionError("unbalanced parentheses in condition")
        parser.take()
        return expr
    if lowered == "all" or _INT_RE.match(token):
        count = None if lowered == "all" else int(token)
        nxt = parser.peek()
        if nxt is None or nxt.lower() != "of":
            raise DetectionError(f"expected 'of' after {token!r}")
        parser.take()
        target = parser.take()
        if target.lower() == "them":
            return _Of(count, None)
        return _Of(count, target)
    if not _IDENT_RE.match(token):
        raise DetectionError(f"invalid identifier {token!r} in condition")
    return _Ident(token)


def _eval_condition(expr: Any, matched_ids: set[str], all_ids: set[str]) -> set[str] | None:
    """Evaluate to the set of contributing identifiers, or None when false."""
    if isinstance(expr, _Ident):
        return {expr.name} if expr.name in matched_ids else None
    if isinstance(expr, _Not):
        return set() if _eval_condition(expr.expr, matched_ids, all_ids) is None else None
    if isinstance(expr, _And):
        left = _eval_condition(expr.left, matched_ids, all_ids)
        right = _eval_condition(expr.right, matched_ids, all_ids)
        if left is None or right is None:
            return None
        return left | right
    if isinstance(expr, _Or):
        left = _eval_condition(expr.left, matched_ids, all_ids)
        right = _eval_condition(expr.right, matched_ids, all_ids)
        if left is None and right is None:
            return None
        if left is None:
            return right
        if right is None:
            return left
        return left & right
    if isinstance(expr, _Of):
        selected = _select_ids(expr.pattern, all_ids)
        hits = selected & matched_ids
        needed = len(selected) if expr.count is None else expr.count
        return hits if len(hits) >= needed and needed > 0 else None
    raise DetectionError(f"unknown condition node: {expr!r}")


def _select_ids(pattern: str | None, all_ids: set[str]) -> set[str]:
    if pattern is None:
        return {name for name in all_ids if not name.startswith("_")}
    regex = _glob_to_regex(pattern)
    return {
        name
        for name in all_ids
        if not name.startswith("_") and re.fullmatch(regex, name, re.IGNORECASE)
    }
