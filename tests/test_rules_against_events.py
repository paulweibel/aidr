"""Regression tests: every event rule must match its true positives and
must not match its false positives.

Fixtures live in tests/events/<rule id>/tp_*.json and fp_*.json. The repo
policy validator refuses rules without fixtures, so coverage here is total
by construction. If a rule change breaks an expectation, either the rule or
the fixture is wrong -- decide which on purpose and change it in the same
commit.
"""
import json
from pathlib import Path

import pytest

import sigma_lite

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"
EVENTS_DIR = Path(__file__).parent / "events"

EVENT_RULES = {doc["id"]: (path, doc) for path, doc in sigma_lite.iter_event_rules(RULES_DIR)}


def _cases(prefix: str):
    cases = []
    for rule_id, (path, doc) in sorted(EVENT_RULES.items()):
        for fixture in sorted((EVENTS_DIR / rule_id).glob(f"{prefix}_*.json")):
            cases.append(pytest.param(doc, fixture, id=f"{path.stem}/{fixture.name}"))
    return cases


@pytest.mark.parametrize("rule,fixture", _cases("tp"))
def test_true_positives_match(rule, fixture):
    event = json.loads(fixture.read_text(encoding="utf-8"))
    assert sigma_lite.rule_matches(rule, event), (
        f"rule '{rule['title']}' failed to match true positive {fixture.name}"
    )


@pytest.mark.parametrize("rule,fixture", _cases("fp"))
def test_false_positives_do_not_match(rule, fixture):
    event = json.loads(fixture.read_text(encoding="utf-8"))
    assert not sigma_lite.rule_matches(rule, event), (
        f"rule '{rule['title']}' wrongly matched false positive {fixture.name}"
    )


def test_no_orphaned_fixture_directories():
    orphans = {d.name for d in EVENTS_DIR.iterdir() if d.is_dir()} - set(EVENT_RULES)
    assert not orphans, f"fixture directories without a matching rule id: {orphans}"
