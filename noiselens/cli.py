import argparse
from collections import Counter
from contextlib import closing
import html
import json
from pathlib import Path
import sqlite3
import sys


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
    if set(policy) - {"schema_version", "protect_rule_ids", "protected_level", "suppressions"}:
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


def analyze(path, policy=None, top=10):
    total, protected_total, removed, protected_removed = 0, 0, 0, 0
    levels, rules, per_policy, per_policy_protected = Counter(), Counter(), Counter(), Counter()
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
                levels[rule["level"]] += 1
                rules[rule["id"]] += 1
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


def write_html(report, path):
    rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(row[k]))}</td>" for k in
                   ("rule_id", "alerts", "share_percent", "distinct_agents")) + "</tr>"
                   for row in report["top_rules"])
    impact = report.get("impact")
    status = "No policy tested" if impact is None else ("REVIEW REQUIRED" if not impact["guard_passed"] else "No protected alerts matched in this dataset")
    Path(path).write_text("<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>Wazuh NoiseLens</title><style>body{background:#101925;color:#e8edf4;font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}"
        "h1{color:#71ddb2}table{border-collapse:collapse;width:100%}td,th{padding:12px;border-bottom:1px solid #344459;text-align:left}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#172538;padding:20px;border-radius:12px}</style>"
        f"<h1>Wazuh NoiseLens</h1><p>{report['total_alerts']} observed alerts · {html.escape(status)}</p>"
        "<p>Measure proposed suppression impact before changing your manager.</p>"
        "<table><tr><th>Rule</th><th>Alerts</th><th>Share %</th><th>Distinct agents</th></tr>"
        + rows + "</table><h2>Impact and limitations</h2><pre>"
        + html.escape(json.dumps(impact or report["interpretation"], indent=2)) + "</pre></html>", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Wazuh suppression impact analysis; no auto-suppression")
    parser.add_argument("alerts", help="Wazuh alerts.json JSONL, or one _source document per line")
    parser.add_argument("--policy")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--json", required=True, dest="json_path")
    parser.add_argument("--html")
    args = parser.parse_args(argv)
    try:
        if args.top <= 0:
            raise InputError("--top must be positive")
        source = Path(args.alerts).resolve()
        inputs = {source}
        if args.policy:
            inputs.add(Path(args.policy).resolve())
        outputs = [Path(p).resolve() for p in (args.json_path, args.html) if p]
        if any(p in inputs for p in outputs) or len(outputs) != len(set(outputs)):
            raise InputError("Outputs must differ from inputs and each other")
        report = analyze(source, load_policy(args.policy) if args.policy else None, args.top)
        Path(args.json_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if args.html:
            write_html(report, args.html)
        print(f"Analyzed {report['total_alerts']} alerts")
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
