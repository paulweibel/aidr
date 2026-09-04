#!/usr/bin/env python3
"""Repository policy validator for aidr detection content.

``sigma check`` validates rules against the Sigma specification; this script
enforces the stricter house policy on top of it:

* every rule carries the metadata an analyst needs at 2am (description of
  useful length, references, explicit false positives, severity);
* IDs are unique v4 UUIDs and titles are unique;
* tags follow the documented grammar, including the extended ``atlas.`` and
  ``owasp.`` namespaces this repo defines (see CONTRIBUTING.md);
* every single-event rule has at least one true-positive and one
  false-positive fixture under tests/events/, keyed by rule id;
* correlation documents reference rule names that exist in the same file.

Exit code is non-zero on any violation, which is what CI keys off.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"
EVENTS_DIR = REPO_ROOT / "tests" / "events"

UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"experimental", "test", "stable"}

ATTACK_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration",
    "impact", "defense-impairment", "stealth",
}
TAG_PATTERNS = [
    re.compile(r"^attack\.t\d{4}(\.\d{3})?$"),
    re.compile(r"^atlas\.aml\.t\d{4}(\.\d{3})?$"),
    re.compile(r"^owasp\.llm(0[1-9]|10)$"),
    re.compile(r"^cve\.\d{4}-\d{4,}$"),
]


class Problems:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, path: Path, message: str) -> None:
        self.items.append(f"{path.relative_to(REPO_ROOT)}: {message}")


def _check_tags(tags: object, path: Path, problems: Problems) -> None:
    if not isinstance(tags, list) or not tags:
        problems.add(path, "tags must be a non-empty list")
        return
    for tag in tags:
        if tag.startswith("attack.") and tag.removeprefix("attack.") in ATTACK_TACTICS:
            continue
        if any(pattern.match(tag) for pattern in TAG_PATTERNS):
            continue
        problems.add(path, f"tag {tag!r} does not match the documented tag grammar")


def _check_common(doc: dict, path: Path, problems: Problems) -> None:
    for field in ("title", "id", "status", "description", "author", "date", "level"):
        if not doc.get(field):
            problems.add(path, f"missing required field {field!r} in {doc.get('title', '<untitled>')!r}")
    if doc.get("id") and not UUID4_RE.match(str(doc["id"])):
        problems.add(path, f"id {doc['id']!r} is not a v4 UUID")
    if doc.get("status") not in STATUSES:
        problems.add(path, f"status {doc.get('status')!r} not in {sorted(STATUSES)}")
    if doc.get("level") not in LEVELS:
        problems.add(path, f"level {doc.get('level')!r} not in {sorted(LEVELS)}")
    if doc.get("date") and not DATE_RE.match(str(doc["date"])):
        problems.add(path, f"date {doc.get('date')!r} must be ISO formatted (YYYY-MM-DD)")
    description = str(doc.get("description") or "")
    if len(description.strip()) < 120:
        problems.add(path, f"description of {doc.get('title')!r} is too thin; explain intent, tuning and gaps")
    references = doc.get("references")
    if not isinstance(references, list) or not references:
        problems.add(path, f"{doc.get('title')!r} needs at least one reference")
    fps = doc.get("falsepositives")
    if not isinstance(fps, list) or not fps:
        problems.add(path, f"{doc.get('title')!r} must declare expected false positives; 'Unknown' is a decision, write it down")
    _check_tags(doc.get("tags"), path, problems)


def _check_fixtures(doc: dict, path: Path, problems: Problems) -> None:
    fixture_dir = EVENTS_DIR / str(doc.get("id"))
    positives = sorted(fixture_dir.glob("tp_*.json"))
    negatives = sorted(fixture_dir.glob("fp_*.json"))
    if not positives or not negatives:
        problems.add(
            path,
            f"{doc.get('title')!r} needs >=1 tp_*.json and >=1 fp_*.json fixture in "
            f"tests/events/{doc.get('id')}/ (found {len(positives)} tp, {len(negatives)} fp)",
        )


def main() -> int:
    problems = Problems()
    seen_ids: dict[str, Path] = {}
    seen_titles: dict[str, Path] = {}

    rule_files = sorted(RULES_DIR.rglob("*.yml"))
    if not rule_files:
        print("no rule files found", file=sys.stderr)
        return 1

    for path in rule_files:
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
        except yaml.YAMLError as exc:
            problems.add(path, f"YAML parse error: {exc}")
            continue
        if not docs:
            problems.add(path, "file contains no YAML documents")
            continue

        local_names = {d.get("name") for d in docs if d.get("name")}
        for doc in docs:
            _check_common(doc, path, problems)

            rule_id = str(doc.get("id"))
            if rule_id in seen_ids:
                problems.add(path, f"duplicate id {rule_id} (also in {seen_ids[rule_id].name})")
            seen_ids[rule_id] = path
            title = str(doc.get("title"))
            if title in seen_titles:
                problems.add(path, f"duplicate title {title!r} (also in {seen_titles[title].name})")
            seen_titles[title] = path

            if "detection" in doc:
                detection = doc["detection"]
                if not isinstance(detection.get("condition"), str):
                    problems.add(path, f"{title!r}: detection.condition must be a single string")
                if not doc.get("logsource"):
                    problems.add(path, f"{title!r}: event rules must declare a logsource")
                _check_fixtures(doc, path, problems)
            elif "correlation" in doc:
                correlation = doc["correlation"]
                if correlation.get("type") not in {"event_count", "value_count", "temporal", "temporal_ordered"}:
                    problems.add(path, f"{title!r}: unknown correlation type {correlation.get('type')!r}")
                for name in correlation.get("rules", []):
                    if name not in local_names:
                        problems.add(path, f"{title!r}: correlation references {name!r}, not defined in this file")
                if not correlation.get("timespan"):
                    problems.add(path, f"{title!r}: correlation must define a timespan")
            else:
                problems.add(path, f"{title!r}: document has neither detection nor correlation")

    if problems.items:
        print(f"FAIL: {len(problems.items)} policy violation(s)\n")
        for item in problems.items:
            print(f"  - {item}")
        return 1

    event_docs = sum(
        1 for p in rule_files for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if d and "detection" in d
    )
    print(f"OK: {len(rule_files)} files, {len(seen_ids)} rule documents ({event_docs} event rules) pass repo policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
