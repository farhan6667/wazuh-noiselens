# Wazuh NoiseLens

**Measure what a proposed alert suppression would hide before deploying it.**

Offline, deterministic analysis of Wazuh `alerts.json` exports: identify alert concentration,
measure candidate exceptions, and flag policies that would suppress protected detections.
Python 3.10+, zero runtime dependencies. No SIEM credentials or cloud service required.

Status: **0.1.0 prototype**. Unit and CLI tests pass locally with synthetic data. Validation
against a representative real-world, sanitized alert corpus is still needed.

## Why this exists

An alert rule generates most of your volume. Suppressing the entire rule may also hide the
few events you need to investigate. NoiseLens measures a proposed rule-scoped exception
against an export, including high-severity and explicitly protected matches.

High volume does not prove an alert is a false positive. NoiseLens measures impact; it does
not classify incidents or modify a Wazuh manager.

## One-minute demo

```sh
python -m noiselens examples/alerts.jsonl --json audit.json --html audit.html
python -m noiselens examples/alerts.jsonl --policy examples/narrow-policy.json --json narrow.json --html narrow.html
python -m noiselens examples/alerts.jsonl --policy examples/broad-policy.json --json broad.json --html broad.html
```

The synthetic dataset has 100 alerts. The narrow example matches 80 and leaves 20,
with no protected matches. The broad example matches 85, including 5 protected alerts:
it produces a report and exits 1 (**review required**).
This teaches the guard, not a production recommendation for rule 60107.

Install with `python -m pip install .`, then use `noiselens` instead of `python -m noiselens`.

## Your data

Copy a representative, authorized Wazuh `alerts.json` export to your analysis workstation:

```sh
noiselens alerts.json --policy reviewed-exceptions.json --top 20 --json impact.json --html impact.html
```

Inputs must be JSON Lines: one alert object per line, or one indexer document with an
`_source` object per line. `rule.id` must be a string; `rule.level` must be an integer.
`agent.id`, if present, must be a string. A whole indexer search-response wrapper is not accepted:
export its `_source` documents one per line first.

## Policy

```json
{
  "schema_version": 1,
  "protected_level": 12,
  "protect_rule_ids": ["100900"],
  "suppressions": [{
    "name": "reviewed-process-only",
    "rule_ids": ["60107"],
    "equals": {"data.win.eventdata.processName": "C:\\Tools\\approved.exe"}
  }]
}
```

- Every suppression explicitly scopes one or more rule IDs.
- Within a suppression, the rule constraint and all `equals` predicates must match.
- Suppressions are ORed; overlapping matches count once in the overall impact.
- Predicates are exact, case-sensitive, type-sensitive comparisons on dotted nested paths.
- Null predicates, regex, wildcard and fuzzy matching are intentionally unsupported.
- High-severity (`>= protected_level`) or named protected rules trigger a review failure.
- Missing fields do not match. Fields with literal dots in their names are not supported.

The policy is an analysis contract, not deployable Wazuh XML. Translate any approved exception
manually and verify its behavior with the real engine before deployment.

## Reports

Rule counts, volume share, distinct reporting agents, severity distribution, union suppression
count, remaining alerts, and protected matches per proposed exception. Reports exclude raw
logs, descriptions, process paths and agent identifiers. Chosen suppression names and rule IDs
are included. HTML is escaped and works offline without scripts or remote assets.

Exit codes: 0 analysis complete/no protected matches, 1 proposed policy matches protected
alerts, 2 invalid input/policy/output error, 130 interrupted. Invalid input aborts without
writing a new partial report. Input/output path collisions are refused.

## Important limits

A guard pass only means no protected alerts in this dataset matched. It does not establish
that an exception is safe on unseen traffic. Pick a representative time window and include
known incidents and benign operations. Severity is an operator-selected safeguard, not ground
truth for maliciousness. No alert-free logs are included, so missed detections cannot be measured.

Duplicate records are counted separately; use non-overlapping exports or deduplicate upstream.
No timestamp-based filtering or trend inference is performed. The tool streams records, but
rule counters and distinct rule/agent combinations grow in memory with data cardinality.
No data is sent over the network; SQLite stores aggregation keys in memory.

## Development and related work

```sh
python -m unittest discover -s tests -v
```

Other projects such as [solsoc](https://github.com/luis-troccoli/solsoc) and
[local_siem_agent](https://github.com/u9u-p/local_siem_agent) tackle AI-assisted triage.
NoiseLens focuses on reproducible proposed-suppression impact, with no model or API dependency.
The two approaches can coexist. See CONTRIBUTING.md and SECURITY.md before submitting samples.

Built by [Syed Farhan Ahmed](https://farhan6667.github.io/portfolio/).
