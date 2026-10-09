import json
from pathlib import Path
import tempfile
import unittest

from noiselens import report as views
from noiselens.cli import InputError, analyze, load_policy, main, matches


def policy():
    return {"schema_version": 1, "protected_level": 12, "protect_rule_ids": ["100900"],
        "suppressions": [{"name": "service account", "rule_ids": ["60107"],
            "equals": {"data.win.eventdata.processName": "C:\\Tools\\approved.exe"}}]}


def alert(rid="60107", level=4, agent="001", process="C:\\Tools\\approved.exe"):
    return {"rule": {"id": rid, "level": level}, "agent": {"id": agent},
        "data": {"win": {"eventdata": {"processName": process}}}, "full_log": "secret"}


class Tests(unittest.TestCase):
    def analyze(self, events, config=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
            return analyze(path, config)

    def test_volume_and_agent_concentration(self):
        result = self.analyze([alert(), alert(), alert(agent="002")])
        self.assertEqual(result["total_alerts"], 3)
        self.assertEqual(result["top_rules"][0]["distinct_agents"], 2)
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("approved.exe", json.dumps(result))

    def test_impact_guard_protects_severity(self):
        result = self.analyze([alert(), alert(level=12)], policy())
        self.assertEqual(result["impact"]["would_suppress"], 2)
        self.assertEqual(result["impact"]["protected_would_suppress"], 1)
        self.assertFalse(result["impact"]["guard_passed"])

    def test_protected_rule_independent_of_severity(self):
        config = policy()
        config["protect_rule_ids"] = ["60107"]
        self.assertFalse(self.analyze([alert()], config)["impact"]["guard_passed"])

    def test_overlapping_suppressions_count_union(self):
        config = policy()
        config["suppressions"].append({"name": "broad", "rule_ids": ["60107"]})
        result = self.analyze([alert()], config)["impact"]
        self.assertEqual(result["would_suppress"], 1)
        self.assertEqual(sum(p["matches"] for p in result["per_suppression"]), 2)

    def test_unrelated_process_preserved(self):
        result = self.analyze([alert(process="C:\\Unknown\\evil.exe")], policy())
        self.assertEqual(result["impact"]["would_suppress"], 0)

    def test_source_wrapper_supported(self):
        self.assertEqual(self.analyze([{"_source": alert()}])["total_alerts"], 1)

    def test_empty_input(self):
        self.assertEqual(self.analyze([], policy())["impact"]["suppression_percent"], 0)

    def test_malformed_record_fails(self):
        with self.assertRaises(InputError):
            self.analyze([alert(), {"message": "not an alert"}])

    def test_boolean_level_rejected(self):
        with self.assertRaises(InputError):
            self.analyze([alert(level=True)])

    def test_type_sensitive_matching(self):
        event = alert()
        event["test"] = False
        self.assertFalse(matches(event, {"rule_ids": ["60107"], "equals": {"test": 0}}))

    def test_missing_field_never_matches_null(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = policy()
            config["suppressions"][0]["equals"] = {"missing": None}
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(config))
            with self.assertRaises(InputError):
                load_policy(path)

    def test_policy_requires_scope_and_rejects_typos(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            for config in [{"schema_version": 1, "suppressions": [{"name": "bad", "rule_ids": []}]},
                           dict(policy(), protected_levle=12)]:
                path.write_text(json.dumps(config))
                with self.assertRaises(InputError):
                    load_policy(path)

    def test_cli_guard_exit_and_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            alerts = folder / "alerts.jsonl"
            config = folder / "policy.json"
            output = folder / "report.json"
            alerts.write_text(json.dumps(alert(level=12)))
            config.write_text(json.dumps(policy()))
            self.assertEqual(main([str(alerts), "--policy", str(config), "--json", str(output)]), 1)
            self.assertTrue(output.exists())

    def test_cli_refuses_overwrite_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            original = json.dumps(alert())
            path.write_text(original)
            self.assertEqual(main([str(path), "--json", str(path)]), 2)
            self.assertEqual(path.read_text(), original)

    def test_html_escaped(self):
        report = self.analyze([alert(rid="<script>alert(1)</script>")])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            path.write_text(views.html_report(report), encoding="utf-8")
            self.assertNotIn("<script>", path.read_text())


if __name__ == "__main__":
    unittest.main()
