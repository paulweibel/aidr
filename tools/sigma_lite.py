"""Minimal Sigma rule evaluator for regression-testing this repository's rules.

This is deliberately not a full Sigma engine. It implements exactly the subset of
the specification used by rules in this repo, so that every detection can be
exercised against captured true-positive and false-positive events in CI. For
production matching use a real backend (pySigma converts these rules cleanly);
for anything the subset does not cover, extend this module and add a test, or
the validator will refuse the rule.

Supported subset
----------------
* Field modifiers: contains, all, startswith, endswith, re, gt, gte, lt, lte
* Plain values: case-insensitive equality with ``*`` and ``?`` wildcards
* Selections: mapping (AND of fields), list of mappings (OR), list of strings
  (keyword search across the serialized event)
* Conditions: ``and``, ``or``, ``not``, parentheses, ``1 of x*``,
  ``all of x*``, ``1 of them``, ``all of them``
* Dotted field paths into nested JSON events (``userIdentity.arn``)

Correlation documents (those with a ``correlation`` key) are parsed for
structure elsewhere but are not evaluated here; stateful windowed matching
belongs in the SIEM.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any, Iterator

import yaml

VALUE_MODIFIERS = {"contains", "all", "startswith", "endswith", "re", "gt", "gte", "lt", "lte"}


def load_documents(path: Path) -> list[dict]:
    """Load all YAML documents from a rule file."""
    with open(path, encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc]


def iter_event_rules(rules_dir: Path) -> Iterator[tuple[Path, dict]]:
    """Yield (path, document) for every document that defines a detection."""
    for path in sorted(rules_dir.rglob("*.yml")):
        for doc in load_documents(path):
            if "detection" in doc:
                yield path, doc


def _field_value(event: dict, field: str) -> Any:
    """Resolve a possibly dotted field path against a nested event."""
    if field in event:
        return event[field]
    current: Any = event
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _scalar_matches(event_value: Any, rule_value: Any, modifiers: list[str]) -> bool:
    """Match one event value against one rule value under the given modifiers."""
    if rule_value is None:
        return event_value is None

    comparisons = {"gt", "gte", "lt", "lte"} & set(modifiers)
    if comparisons:
        left = _as_number(event_value)
        right = _as_number(rule_value)
        if left is None or right is None:
            return False
        op = comparisons.pop()
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[op]

    if "re" in modifiers:
        if event_value is None:
            return False
        return re.search(str(rule_value), str(event_value)) is not None

    if event_value is None:
        return False
    haystack = str(event_value).lower()
    needle = str(rule_value).lower()

    if "contains" in modifiers:
        return needle in haystack
    if "startswith" in modifiers:
        return haystack.startswith(needle)
    if "endswith" in modifiers:
        return haystack.endswith(needle)

    if isinstance(rule_value, (int, float)) and not isinstance(rule_value, bool):
        number = _as_number(event_value)
        return number is not None and number == float(rule_value)
    return fnmatch.fnmatchcase(haystack, needle)


def _values_match(event_value: Any, rule_value: Any, modifiers: list[str]) -> bool:
    """Handle list-valued rule entries (OR, or AND with the ``all`` modifier)."""
    event_values = event_value if isinstance(event_value, list) else [event_value]

    def one(rv: Any) -> bool:
        return any(_scalar_matches(ev, rv, modifiers) for ev in event_values)

    if isinstance(rule_value, list):
        if "all" in modifiers:
            return all(one(rv) for rv in rule_value)
        return any(one(rv) for rv in rule_value)
    return one(rule_value)


def _serialize(event: Any) -> str:
    if isinstance(event, dict):
        return " ".join(_serialize(v) for v in event.values())
    if isinstance(event, list):
        return " ".join(_serialize(v) for v in event)
    return str(event)


def _selection_matches(selection: Any, event: dict) -> bool:
    if isinstance(selection, dict):
        for key, rule_value in selection.items():
            field, *modifiers = key.split("|")
            unknown = set(modifiers) - VALUE_MODIFIERS
            if unknown:
                raise ValueError(f"unsupported modifier(s) {unknown} on field {field!r}")
            if not _values_match(_field_value(event, field), rule_value, modifiers):
                return False
        return True
    if isinstance(selection, list):
        if all(isinstance(item, dict) for item in selection):
            return any(_selection_matches(item, event) for item in selection)
        blob = _serialize(event).lower()
        return any(str(item).lower() in blob for item in selection)
    raise ValueError(f"unsupported selection structure: {type(selection)!r}")


class _ConditionParser:
    """Recursive-descent parser for the supported condition grammar."""

    def __init__(self, condition: str, results: dict[str, bool]):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", condition)
        self.pos = 0
        self.results = results

    def parse(self) -> bool:
        value = self._expr()
        if self.pos != len(self.tokens):
            raise ValueError(f"trailing tokens in condition at {self.tokens[self.pos:]}")
        return value

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _expr(self) -> bool:
        value = self._term()
        while self._peek() == "or":
            self._take()
            value = self._term() or value
        return value

    def _term(self) -> bool:
        value = self._factor()
        while self._peek() == "and":
            self._take()
            value = self._factor() and value
        return value

    def _factor(self) -> bool:
        token = self._peek()
        if token == "not":
            self._take()
            return not self._factor()
        if token == "(":
            self._take()
            value = self._expr()
            if self._take() != ")":
                raise ValueError("unbalanced parentheses in condition")
            return value
        if token in {"1", "all"}:
            quantifier = self._take()
            if self._take() != "of":
                raise ValueError(f"expected 'of' after {quantifier!r}")
            pattern = self._take()
            names = (
                list(self.results)
                if pattern == "them"
                else [n for n in self.results if fnmatch.fnmatchcase(n, pattern)]
            )
            if not names:
                raise ValueError(f"condition pattern {pattern!r} matches no selection")
            values = [self.results[n] for n in names]
            return all(values) if quantifier == "all" else any(values)
        name = self._take()
        if name not in self.results:
            raise ValueError(f"condition references unknown selection {name!r}")
        return self.results[name]


def rule_matches(rule: dict, event: dict) -> bool:
    """Evaluate a single-event Sigma rule document against one event."""
    detection = rule["detection"]
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise ValueError("detection.condition must be a single string")
    results = {
        name: _selection_matches(sel, event)
        for name, sel in detection.items()
        if name != "condition"
    }
    return _ConditionParser(condition, results).parse()
