# Compare a narrow exception with a broad one

The included dataset contains 100 synthetic alerts. It gives you a small example
of how an exception can hide alerts you intended to keep.

Run these commands from the repository directory with Python 3.10 or newer:

```sh
python -m noiselens examples/alerts.jsonl --json audit.json --html audit.html
python -m noiselens examples/alerts.jsonl --policy examples/narrow-policy.json --json narrow.json --html narrow.html
python -m noiselens examples/alerts.jsonl --policy examples/broad-policy.json --json broad.json --html broad.html
```

The first command counts the dataset and should exit 0. The narrow policy matches
80 alerts, leaves 20 and matches no protected alerts. It should also exit 0.

The broad policy matches 85 alerts, including five protected alerts. It writes
the report and exits 1 so you can inspect the problem. Open `broad.html` and
compare it with `narrow.html` to see the extra matches.

These counts describe the fixtures. They aren't measured reductions in false
positives, and a passing guard doesn't prove an exception is safe on other data.

For your own analysis, export one alert or indexer `_source` object per JSON line.
Start with counts, review the underlying alerts, then write an exception scoped
to the rule IDs and exact field values you intend to examine. Include known
incidents in the dataset and protect the rules you need to retain.

The policy file only defines an analysis. If you approve an exception, translate
it into Wazuh rules and verify it on a test manager before deployment. See the
[README](../README.md) for the policy format and data handling limits.
