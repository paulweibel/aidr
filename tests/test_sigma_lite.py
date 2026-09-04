"""Unit tests for the evaluator itself, independent of any repo rule."""
import pytest

import sigma_lite


def _rule(detection):
    return {"title": "unit", "detection": detection}


def test_equality_is_case_insensitive_with_wildcards():
    rule = _rule({"selection": {"cs-method": "post", "cs-host": "*.example.com"}, "condition": "selection"})
    assert sigma_lite.rule_matches(rule, {"cs-method": "POST", "cs-host": "api.example.com"})
    assert not sigma_lite.rule_matches(rule, {"cs-method": "GET", "cs-host": "api.example.com"})


def test_contains_all_requires_every_value():
    rule = _rule({"selection": {"CommandLine|contains|all": ["ollama", "serve"]}, "condition": "selection"})
    assert sigma_lite.rule_matches(rule, {"CommandLine": "bash -c 'OLLAMA_HOST=127.0.0.1 ollama serve'"})
    assert not sigma_lite.rule_matches(rule, {"CommandLine": "ollama run llama3.1"})


def test_numeric_gt_comparison():
    rule = _rule({"selection": {"cs-bytes|gt": 100}, "condition": "selection"})
    assert sigma_lite.rule_matches(rule, {"cs-bytes": 101})
    assert not sigma_lite.rule_matches(rule, {"cs-bytes": 100})
    assert not sigma_lite.rule_matches(rule, {"cs-bytes": "not-a-number"})


def test_dotted_field_paths_resolve_nested_events():
    rule = _rule({"selection": {"userIdentity.arn|contains": ":user/"}, "condition": "selection"})
    assert sigma_lite.rule_matches(rule, {"userIdentity": {"arn": "arn:aws:iam::1:user/x"}})
    assert not sigma_lite.rule_matches(rule, {"userIdentity": {"arn": "arn:aws:iam::1:role/x"}})


def test_condition_not_and_one_of_pattern():
    detection = {
        "selection_a": {"f": "hit"},
        "selection_b": {"g": "hit"},
        "filter_main": {"env": "dev"},
        "condition": "1 of selection_* and not filter_main",
    }
    rule = _rule(detection)
    assert sigma_lite.rule_matches(rule, {"f": "hit", "env": "prod"})
    assert not sigma_lite.rule_matches(rule, {"f": "hit", "env": "dev"})
    assert not sigma_lite.rule_matches(rule, {"h": "miss", "env": "prod"})


def test_keyword_list_selection_searches_whole_event():
    rule = _rule({"keywords": ["canary-token"], "condition": "keywords"})
    assert sigma_lite.rule_matches(rule, {"response": "leaked CANARY-TOKEN here", "user": "x"})
    assert not sigma_lite.rule_matches(rule, {"response": "clean", "user": "x"})


def test_unknown_modifier_is_rejected_not_ignored():
    rule = _rule({"selection": {"f|base64offset": "x"}, "condition": "selection"})
    with pytest.raises(ValueError):
        sigma_lite.rule_matches(rule, {"f": "x"})


def test_condition_referencing_missing_selection_is_rejected():
    rule = _rule({"selection": {"f": "x"}, "condition": "selection and ghost"})
    with pytest.raises(ValueError):
        sigma_lite.rule_matches(rule, {"f": "x"})
