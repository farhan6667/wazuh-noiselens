import argparse
from collections import Counter
from datetime import datetime, timezone
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3
import sys
from importlib import resources

from . import report as views


class InputError(Exception):
    pass


def field(event, path):
    value = event
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def load_policy(path):
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise InputError("Cannot read policy JSON") from None
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise InputError("Policy needs schema_version 1")
    if set(policy) - {"$schema", "schema_version", "protect_rule_ids", "protected_level", "suppressions"}:
        raise InputError("Unknown policy key")
    level = policy.get("protected_level", 12)
    if type(level) is not int or not 0 <= level <= 16:
        raise InputError("protected_level must be an integer from 0 to 16")
    protected = policy.get("protect_rule_ids", [])
    if not isinstance(protected, list) or not all(isinstance(x, str) for x in protected):
        raise InputError("protect_rule_ids must be a string array")
    suppressions = policy.get("suppressions")
    if not isinstance(suppressions, list) or not suppressions:
        raise InputError("Policy requires a non-empty suppressions array")
    names = set()
    for rule in suppressions:
        if not isinstance(rule, dict) or set(rule) - {"name", "rule_ids", "equals"}:
            raise InputError("Unknown suppression key")
        if not isinstance(rule.get("name"), str) or not rule["name"].strip() or rule["name"] in names:
            raise InputError("Suppression names must be unique non-empty strings")
        names.add(rule["name"])
        if not isinstance(rule.get("rule_ids"), list) or not rule["rule_ids"] or not all(isinstance(x, str) for x in rule["rule_ids"]):
            raise InputError("Every suppression must explicitly scope string rule_ids")
        equals = rule.get("equals", {})
        if not isinstance(equals, dict) or not all(isinstance(k, str) and k and
            all(part for part in k.split(".")) and isinstance(v, (str, int, bool)) for k, v in equals.items()):
            raise InputError("equals must map dotted paths to scalar values; null is not allowed")
    return policy


def matches(event, policy):
    if event["rule"]["id"] not in policy["rule_ids"]:
        return False
    # Type-sensitive comparisons prevent False matching integer 0, for example.
    return all(type(field(event, key)) is type(value) and field(event, key) == value
               for key, value in policy.get("equals", {}).items())



_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)$")


def parse_timestamp(value):
    """Wazuh alert timestamp to an aware UTC datetime, or None. Offsets such as +0000 and +05:00 are both read."""
    if not isinstance(value, str):
        return None
    m = _TS.match(value.strip())
    if not m:
        return None
    base, frac, off = m.groups()
    off = "+00:00" if off == "Z" else (off if ":" in off else off[:3] + ":" + off[3:])
    try:
        return datetime.fromisoformat(f"{base}.{(frac or '0')[:6].ljust(6, '0')}{off}").astimezone(timezone.utc)
    except ValueError:
        return None


MAX_DISTINCT_VALUES = 5000


def analyze(path, policy=None, top=10, breakdown=None, collect=None):
    total, protected_total, removed, protected_removed = 0, 0, 0, 0
    levels, rules, per_policy, per_policy_protected = Counter(), Counter(), Counter(), Counter()
    groups, first_ts, last_ts, no_ts = Counter(), None, None, 0
    policy_names = [p["name"] for p in policy["suppressions"]] if policy else []
    # Store only rule/agent combinations in memory, never full logs or descriptions.
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE agents (rule TEXT, agent TEXT, PRIMARY KEY(rule, agent))")
        with Path(path).open(encoding="utf-8-sig") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    raise InputError(f"Invalid JSON on line {number}; no partial report written") from None
                if isinstance(event, dict) and "_source" in event:
                    event = event["_source"]
                rule = event.get("rule") if isinstance(event, dict) else None
                if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or type(rule.get("level")) is not int or not 0 <= rule["level"] <= 16:
                    raise InputError(f"Missing/invalid rule.id or rule.level on line {number}")
                agent = event.get("agent", {})
                if not isinstance(agent, dict):
                    raise InputError(f"Invalid agent on line {number}")
                agent_id = agent.get("id")
                if agent_id is not None and not isinstance(agent_id, str):
                    raise InputError(f"agent.id must be a string on line {number}")
                total += 1
                if breakdown and collect is not None and rule["id"] == breakdown[0]:
                    collect["alerts"] = collect.get("alerts", 0) + 1
                    value = field(event, breakdown[1])
                    if type(value) in (str, int, bool):
                        values = collect.setdefault("values", Counter())
                        if value in values or len(values) < MAX_DISTINCT_VALUES:
                            values[value] += 1
                        else:
                            collect["truncated"] = True
                    else:
                        collect["missing"] = collect.get("missing", 0) + 1
                levels[rule["level"]] += 1
                rules[rule["id"]] += 1
                rule_groups = rule.get("groups")
                if isinstance(rule_groups, list):
                    for group in set(g for g in rule_groups if isinstance(g, str)):
                        groups[group] += 1
                stamp = parse_timestamp(event.get("timestamp")) if isinstance(event, dict) else None
                if stamp is None:
                    no_ts += 1
                else:
                    first_ts = stamp if first_ts is None or stamp < first_ts else first_ts
                    last_ts = stamp if last_ts is None or stamp > last_ts else last_ts
                if agent_id is not None:
                    db.execute("INSERT OR IGNORE INTO agents VALUES (?,?)", (rule["id"], agent_id))
                protected = bool(policy and (rule["level"] >= policy.get("protected_level", 12) or
                                 rule["id"] in policy.get("protect_rule_ids", [])))
                protected_total += protected
                hit = False
                if policy:
                    for suppression in policy["suppressions"]:
                        if matches(event, suppression):
                            hit = True
                            per_policy[suppression["name"]] += 1
                            per_policy_protected[suppression["name"]] += protected
                # Union count: overlapping policies do not double-count an alert.
                removed += hit
                protected_removed += hit and protected
        agent_counts = dict(db.execute("SELECT rule, count(*) FROM agents GROUP BY rule"))
    report = {"schema_version": 1, "mode": "offline-impact" if policy else "offline-audit",
              "total_alerts": total, "severity_distribution": dict(sorted(levels.items())),
              "top_rules": [{"rule_id": rid, "alerts": count,
                  "share_percent": round(100 * count / total, 2),
                  "distinct_agents": agent_counts.get(rid, 0)}
                 for rid, count in rules.most_common(top)],
              "top_groups": [{"group": g, "alerts": c, "share_percent": round(100 * c / total, 2)}
                             for g, c in groups.most_common(top)],
              "coverage": {"first_utc": first_ts.isoformat() if first_ts else None,
                           "last_utc": last_ts.isoformat() if last_ts else None,
                           "alerts_without_valid_timestamp": no_ts},
              "interpretation": "Volume does not establish false positives. Observed dataset only; duplicate input rows count separately."}
    if policy:
        report["impact"] = {"would_suppress": removed, "remaining": total - removed,
            "suppression_percent": round(100 * removed / total, 2) if total else 0,
            "protected_alerts": protected_total, "protected_would_suppress": protected_removed,
            "guard_passed": protected_removed == 0,
            "per_suppression": [{"name": name, "matches": per_policy[name],
                "protected_matches": per_policy_protected[name]} for name in policy_names],
            "interpretation": "Guard failure requires review. Guard pass is not proof that a suppression is safe; coverage is limited to this dataset."}
    return report


def write_text(path, text):
    Path(path).write_text(text, encoding="utf-8")


def parse_breakdown(text):
    rule_id, sep, path = text.partition(":")
    if not sep or not rule_id.strip() or not path.strip() or not all(part for part in path.split(".")):
        raise InputError("--breakdown needs RULE_ID:dotted.field.path, for example 60107:data.win.eventdata.processName")
    return rule_id.strip(), path.strip()


def group_by_path(values, depth):
    """Fold values like C:\\Tools\\a.exe or /var/log/x into their first `depth` folders, so a long tail shows as a few directories."""
    folded = Counter()
    for value, count in values.items():
        parts = [p for p in re.split(r"[\\/]+", str(value)) if p]
        lead = "/" if str(value).startswith("/") else ""
        folded[lead + "/".join(parts[:depth]) if parts else str(value)] += count
    return folded


def print_breakdown(breakdown, collect, limit, depth=None):
    rule_id, path = breakdown
    values = collect.get("values", Counter())
    if depth:
        values = group_by_path(values, depth)
    print(f"Top values of {views.printable(path)} for rule {views.printable(rule_id)}: "
          f"{collect.get('alerts', 0)} alerts, {len(values)} distinct values, {collect.get('missing', 0)} without that field")
    seen_total = sum(values.values())
    running = 0
    for value, count in values.most_common(limit):
        running += count
        share = f"{100 * running / seen_total:5.1f}%" if seen_total else "    -"
        print(f"{count:>8}  {share}  {views.printable(value)}")
    print("(the middle column is the running share of the alerts that carry this field)")
    if collect.get("truncated"):
        print(f"(stopped counting new distinct values after {MAX_DISTINCT_VALUES})")
    print("These values are shown on this terminal only. They are never written to a report.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Wazuh suppression impact analysis; no auto-suppression")
    parser.add_argument("alerts", nargs="?", help="Wazuh alerts.json JSONL, or one _source document per line")
    parser.add_argument("--policy")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--html")
    parser.add_argument("--markdown", help="Markdown summary, for example for $GITHUB_STEP_SUMMARY")
    parser.add_argument("--breakdown", metavar="RULE_ID:FIELD",
                        help="Print the most common values of one field for one rule (terminal only), to help write a narrow exception")
    parser.add_argument("--path-depth", type=int, metavar="N",
                        help="With --breakdown, fold file paths into their first N folders so noise shows up as a few directories")
    parser.add_argument("--print-schema", action="store_true", help="Print the policy JSON Schema and exit")
    args = parser.parse_args(argv)
    try:
        if args.print_schema:
            print(resources.files("noiselens").joinpath("policy.schema.json").read_text(encoding="utf-8"), end="")
            return 0
        if not args.alerts or not args.json_path:
            parser.error("the alerts file and --json are required")
        if args.top <= 0:
            raise InputError("--top must be positive")
        source = Path(args.alerts).resolve()
        inputs = {source}
        if args.policy:
            inputs.add(Path(args.policy).resolve())
        outputs = [Path(p).resolve() for p in (args.json_path, args.html, args.markdown) if p]
        if any(p in inputs for p in outputs) or len(outputs) != len(set(outputs)):
            raise InputError("Outputs must differ from inputs and each other")
        if args.path_depth is not None and (args.path_depth < 1 or not args.breakdown):
            raise InputError("--path-depth needs --breakdown and a number of 1 or more")
        breakdown = parse_breakdown(args.breakdown) if args.breakdown else None
        collect = {}
        report = analyze(source, load_policy(args.policy) if args.policy else None, args.top, breakdown, collect)
        Path(args.json_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if args.html:
            write_text(args.html, views.html_report(report))
        if args.markdown:
            write_text(args.markdown, views.markdown_report(report))
        print(f"Analyzed {report['total_alerts']} alerts")
        if breakdown:
            print_breakdown(breakdown, collect, args.top, args.path_depth)
        if report.get("impact", {}).get("guard_passed") is False:
            print("REVIEW REQUIRED: proposed policy would suppress protected alerts", file=sys.stderr)
            return 1
        return 0
    except InputError as exc:
        print(f"noiselens: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("noiselens: cannot read input or write report", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
