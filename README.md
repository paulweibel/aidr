# aidr — detections for the GenAI attack surface

Detection-as-code for the ways organizations actually get hurt by and through
LLMs: shadow AI and data exfiltration into external models, LLMjacking of
cloud AI services, prompt injection and system-prompt leakage at the
application layer, agent tool abuse (SSRF via tool calls, rogue MCP servers),
and exposed local model servers. Rules are Sigma where Sigma is honest about
the job, native Splunk SPL where the detection needs state, and every event
rule ships with true-positive and false-positive fixtures that CI evaluates
on every commit.

This started as the detection backlog I wanted to exist while watching GenAI
tooling spread through an enterprise faster than its logging did.

## What's here

```
rules/            16 Sigma documents (14 event rules, 2 correlation chains)
  network/        shadow-AI visibility, large uploads to GenAI services
  cloud/          AWS Bedrock logging tamper, guardrail removal (CloudTrail)
  application/    prompt injection phrases, invisible-Unicode smuggling,
                  system-prompt canary leak, agent SSRF via tool calls
  linux/          GenAI API calls from server CLIs, exposed Ollama
  windows/        MCP config tampering by script interpreters (persistence)
  correlations/   Sigma v2 meta-rules: Bedrock logging recon→disable
                  (temporal), guardrail-block burst (event_count)
splunk/           the Splunk-native layer
  savedsearches/  annotated SPL: cumulative upload volume, first-seen
                  Bedrock (principal, model) pairs, per-user token z-scores,
                  PCRE twin of the Unicode rule, ordered recon→disable
tools/            repo policy validator, coverage generator, and the
                  minimal Sigma evaluator that powers the fixture tests
tests/            54 tests: per-rule TP/FP regression, evaluator units, and
                  triage tool tests
triage/           LLM-drafted triage notes with the security controls
                  written down (docs/triage-threat-model.md)
docs/             detection philosophy, telemetry prerequisites, coverage
                  map, related work, triage threat model
CHANGELOG.md      release notes per tagged version
```

## Quickstart

```bash
pip install -r requirements-dev.txt
make            # yamllint + repo policy + sigma check + 54 tests
make convert    # Sigma → Splunk into dist/rules.splunk.txt
```

Every rule can be exercised without a SIEM:

```bash
python3 - <<'PY'
import json, sys; sys.path.insert(0, "tools"); import sigma_lite
path, rule = next(p for p in sigma_lite.iter_event_rules(__import__("pathlib").Path("rules"))
                  if "canary" in str(p[0]))
event = json.load(open("tests/events/8ac5da19-b351-4f09-9860-6e13461ae260/tp_canary_leak.json"))
print(rule["title"], "->", sigma_lite.rule_matches(rule, event))
PY
```

## Design decisions worth arguing about

- **Fixtures are mandatory.** The validator refuses any event rule without at
  least one true-positive and one false-positive event under `tests/events/`.
  A reported false positive gets fixed by adding the offending event as a
  fixture, so it can never quietly return.
- **Declared false positives are mandatory.** Every rule names the benign
  activity it will collide with. The Unicode-smuggling rule filtering emoji
  subdivision flags (which legitimately contain tag characters) is the level
  of specificity this policy is meant to force.
- **Severity means routing.** `low` rules feed dashboards and correlations;
  only sequences and near-deterministic signals (canary leak, logging
  recon→disable) earn `high`/`critical`. Rationale in
  [docs/detection-philosophy.md](docs/detection-philosophy.md).
- **Portable core, native state.** Sigma cannot sum bytes or keep baselines,
  so those detections are SPL with the reasoning in comments instead of
  pretending otherwise.
- **Current frameworks.** ATT&CK tags validate in CI against the live
  dataset and reflect the v19 restructure (`defense-impairment`, `stealth`,
  T1685.x for log tampering); ATLAS and OWASP LLM Top 10 (2025) mappings are
  enforced by the same tag grammar. Full map:
  [docs/coverage.md](docs/coverage.md).

## Limitations, stated plainly

String rules do not solve semantic prompt injection; the phrase rule says so
in its own description and sits at `low` accordingly. The application-layer
rules assume gateway logging that many shops have not turned on yet —
[docs/telemetry-prereqs.md](docs/telemetry-prereqs.md) covers what to enable
and the privacy conversation that prompt logging requires. Correlation rules
depend on backend support for Sigma v2 meta-rules; fallbacks are noted per
rule. The test harness evaluates the Sigma subset these rules use, not the
whole specification — production matching belongs to real backends, which
`make convert` targets.

## Related work

This repo cites its neighbors rather than pretending they don't exist:
Splunk Threat Research's Bedrock content, Elastic's LLM detections, Agent
Threat Rules, agentshield's Sigma set, and Sysdig's LLMjacking research.
What's different here and what's borrowed is spelled out in
[docs/related-work.md](docs/related-work.md).

## License

MIT. Rule metadata, fixtures, and docs included.
