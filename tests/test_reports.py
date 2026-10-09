import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from noiselens import report as views
from noiselens.cli import InputError, analyze, load_policy, main, parse_breakdown

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SCHEMA = Path(__file__).resolve().parent.parent / "noiselens" / "policy.schema.json"


def event(rid="60107", level=4, agent="001", process="a.exe"):
    return {"rule": {"id": rid, "level": level}, "agent": {"id": agent},
            "data": {"win": {"eventdata": {"processName": process}}}}


def write_alerts(tmp, events):
    path = Path(tmp) / "alerts.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return path


class ReportTests(unittest.TestCase):
    def test_html_for_the_broad_demo_policy_says_review_required(self):
        report = analyze(EXAMPLES / "alerts.jsonl", load_policy(EXAMPLES / "broad-policy.json"))
        out = views.html_report(report)
        self.assertIn("REVIEW REQUIRED", out)
        self.assertIn("default-src 'none'", out)
        self.assertNotIn("<script", out)

    def test_html_for_the_narrow_demo_policy_passes(self):
        report = analyze(EXAMPLES / "alerts.jsonl", load_policy(EXAMPLES / "narrow-policy.json"))
        self.assertIn("No protected alert matched", views.html_report(report))

    def test_html_and_markdown_escape_hostile_names(self):
        policy = {"schema_version": 1, "suppressions": [{"name": "<img src=x>|bad", "rule_ids": ["60107"]}]}
        with tempfile.TemporaryDirectory() as tmp:
            report = analyze(write_alerts(tmp, [event(rid="60107")]), load_policy_from(tmp, policy))
        out = views.html_report(report)
        self.assertNotIn("<img src=x>", out)
        self.assertIn(r"\|bad", views.markdown_report(report))

    def test_markdown_has_one_summary_line(self):
        report = analyze(EXAMPLES / "alerts.jsonl", load_policy(EXAMPLES / "broad-policy.json"))
        md = views.markdown_report(report)
        self.assertIn("100 alerts analyzed** · would hide **85**", md)

    def test_cli_writes_all_outputs_and_exits_1_on_a_protected_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            code = main([str(EXAMPLES / "alerts.jsonl"), "--policy", str(EXAMPLES / "broad-policy.json"),
                         "--json", str(t / "r.json"), "--html", str(t / "r.html"), "--markdown", str(t / "r.md")])
            self.assertEqual(code, 1)
            for name in ("r.json", "r.html", "r.md"):
                self.assertTrue((t / name).stat().st_size > 0)

    def test_markdown_cannot_overwrite_the_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_alerts(tmp, [event()])
            before = path.read_text(encoding="utf-8")
            self.assertEqual(main([str(path), "--json", str(Path(tmp) / "r.json"), "--markdown", str(path)]), 2)
            self.assertEqual(path.read_text(encoding="utf-8"), before)


def load_policy_from(tmp, policy):
    path = Path(tmp) / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return load_policy(path)


class BreakdownTests(unittest.TestCase):
    def run_cli(self, tmp, events, spec, *extra):
        path = write_alerts(tmp, events)
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([str(path), "--json", str(Path(tmp) / "r.json"), "--breakdown", spec, *extra])
        return code, out.getvalue(), (Path(tmp) / "r.json").read_text(encoding="utf-8")

    def test_lists_top_values_on_stdout_and_keeps_them_out_of_the_report(self):
        events = [event(process="secret-tool.exe")] * 3 + [event(process="other.exe")] + [event(rid="999", process="nope.exe")]
        with tempfile.TemporaryDirectory() as tmp:
            code, out, report = self.run_cli(tmp, events, "60107:data.win.eventdata.processName")
        self.assertEqual(code, 0)
        self.assertIn("secret-tool.exe", out)
        self.assertNotIn("nope.exe", out)
        self.assertIn("4 alerts, 2 distinct", out)
        self.assertNotIn("secret-tool.exe", report)

    def test_counts_alerts_without_the_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_cli(tmp, [event(), {"rule": {"id": "60107", "level": 4}}], "60107:data.win.eventdata.processName")
        self.assertIn("1 without that field", out)

    def test_terminal_control_characters_are_neutralised(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_cli(tmp, [event(process="\x1b[31mred\x1b[0m\x07")], "60107:data.win.eventdata.processName")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_long_values_are_cut(self):
        self.assertLessEqual(len(views.printable("x" * 500)), 120)

    def test_bad_specs_are_refused(self):
        for bad in ("60107", ":a.b", "60107:", "60107:a..b"):
            with self.assertRaises(InputError):
                parse_breakdown(bad)


class SchemaTests(unittest.TestCase):
    def test_schema_keys_match_the_validator(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        top = set(schema["properties"]) - {"$schema"}
        self.assertEqual(top, {"schema_version", "protected_level", "protect_rule_ids", "suppressions"})
        item = schema["properties"]["suppressions"]["items"]["properties"]
        self.assertEqual(set(item), {"name", "rule_ids", "equals"})

    def test_policy_may_carry_a_schema_pointer(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = {"$schema": "x", "schema_version": 1, "suppressions": [{"name": "n", "rule_ids": ["1"]}]}
            self.assertEqual(load_policy_from(tmp, policy)["schema_version"], 1)

    def test_print_schema_exits_zero(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["--print-schema"]), 0)
        self.assertIn("Wazuh NoiseLens policy", out.getvalue())


if __name__ == "__main__":
    unittest.main()
