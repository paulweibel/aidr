# aidr — detections for the GenAI attack surface

[![tests](https://github.com/paulweibel/aidr/actions/workflows/ci.yml/badge.svg)](https://github.com/paulweibel/aidr/actions/workflows/ci.yml)

Detection-as-code for the ways organizations actually get hurt by and through
LLMs. First cut is the cloud control plane: AWS Bedrock logging tamper and
guardrail removal, from CloudTrail. Rules are Sigma, and every event rule
ships with true-positive and false-positive fixtures that CI evaluates on
every commit.

This started as the detection backlog I wanted to exist while watching GenAI
tooling spread through an enterprise faster than its logging did.

## What's here

```
rules/cloud/      2 Sigma rules (CloudTrail): Bedrock invocation logging
                  disabled, guardrail deleted or modified
tests/            TP/FP fixtures per rule under tests/events/<rule id>/,
                  per-rule regression tests, evaluator unit tests
tools/            repo policy validator and the minimal Sigma evaluator
                  that powers the fixture tests
.github/          CI: pytest and the policy validator on every push
```

## Quickstart

```bash
pip install pytest pyyaml
pytest                      # 14 tests
python tools/validate.py    # repo policy
```

## Design decisions worth arguing about

- **Fixtures are mandatory.** The validator refuses any event rule without at
  least one true-positive and one false-positive event under `tests/events/`.
  A reported false positive gets fixed by adding the offending event as a
  fixture, so it can never quietly return.
- **Declared false positives are mandatory.** Every rule names the benign
  activity it will collide with. The guardrail rule naming ML teams that
  iterate on guardrail policy, and sending `UpdateGuardrail` through change
  management before paging, is the level of specificity this policy is meant
  to force.
- **Severity means routing.** Logging disabled is `high`: rare, and it blinds
  everything downstream. Guardrail changes are `medium` because updates are
  noisy wherever teams tune policy.
- **Current frameworks.** ATT&CK tags reflect the v19 restructure
  (`defense-impairment`, T1685.x for log tampering); ATLAS and OWASP LLM
  Top 10 (2025) tags are enforced by the same tag grammar in the validator.

## Limitations, stated plainly

Two rules, one data source. The test harness evaluates the Sigma subset these
rules use, not the whole specification; production matching belongs to real
backends, and pySigma converts these rules cleanly.

## Next

Not built yet:

- shadow AI and large uploads to GenAI services (proxy)
- prompt injection phrases, invisible-Unicode smuggling, system-prompt canary
  leak, agent SSRF via tool calls (LLM gateway)
- GenAI API calls from server CLIs, exposed Ollama (Linux)
- MCP config tampering by script interpreters (Windows)
- Sigma v2 correlations: Bedrock logging recon then disable, guardrail-block
  burst
- SPL for what Sigma can't hold: cumulative upload volume, first-seen
  (principal, model) pairs, per-user token z-scores

## Related work

This repo cites its neighbors rather than pretending they don't exist:
Splunk Threat Research's Bedrock content, Sysdig's LLMjacking research and
Abstract Security's Bedrock write-up, referenced in the rules where they
overlap.

## License

MIT.
