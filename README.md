# Wazuh NoiseLens

See which alerts a proposed Wazuh exception would hide.

NoiseLens reads an exported `alerts.json` file on your workstation. It counts
alerts by rule and measures how a proposed exception would affect that dataset.
If the exception matches a protected alert, the command exits with a review failure.

Requires Python 3.10 or newer, with no runtime dependencies. Analysis runs offline.

Version 0.1.0 is a prototype. Local unit and CLI tests pass with synthetic data.
Testing with representative, sanitized operator data is still pending.

## Before suppressing a noisy rule

A busy rule may contain both routine activity and events worth investigating.
NoiseLens lets you test a narrower exception against an export and inspect what
it matches, including alerts with high severity or rule IDs you've protected.

Volume alone doesn't tell you whether an alert is a false positive. You still
need to review the matching events and test an approved exception on a manager.
NoiseLens measures the proposed impact and leaves that decision with you.

## Run the demo

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

Each suppression must name one or more rule IDs. An alert matches only when
its rule ID and every `equals` predicate match. Multiple suppressions are combined
with OR, and overlapping matches count once in the overall total.

Comparisons use exact values, including letter case and value type. Predicates
use dotted paths to reach nested fields. Missing fields don't match, and literal
dots in field names aren't supported. Null predicates, regex, wildcards and fuzzy
matching aren't supported either.

An alert at or above `protected_level`, or with a named protected rule ID, triggers
a review failure if it matches a suppression.

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
known incidents and benign operations. Severity is an safeguard selected by the operator, not ground
truth for maliciousness. No logs that produced no alerts are included, so missed detections cannot be measured.

Duplicate records are counted separately; use exports without overlapping records or deduplicate upstream.
No filtering by timestamp or trend inference is performed. The tool streams records, but
rule counters and distinct rule/agent combinations grow in memory with data cardinality.
No data is sent over the network; SQLite stores aggregation keys in memory.

## Development and related work

```sh
python -m unittest discover -s tests -v
```

Other projects such as [solsoc](https://github.com/luis-troccoli/solsoc) and
[local_siem_agent](https://github.com/u9u-p/local_siem_agent) tackle triage with language models.
NoiseLens focuses on reproducible impact of proposed suppressions, with no model or API dependency.
The two approaches can coexist. Read [contribution notes](CONTRIBUTING.md) and [security notes](SECURITY.md) before submitting samples.

Built by [Syed Farhan Ahmed](https://farhan6667.github.io/portfolio/).

For the demo commands and expected results, see [the demo guide](docs/demo.md).
