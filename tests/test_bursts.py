import json
from pathlib import Path
import tempfile
import unittest

from noiselens import report as views
from noiselens.cli import analyze, main


def alert(rid="60107", agent="001", ts="2026-10-05T09:00:00Z"):
    a = {"rule": {"id": rid, "level": 4}, "agent": {"id": agent}}
    if ts is not None:
        a["timestamp"] = ts
    return a


def run(events, minutes):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "a.jsonl"
        path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
        return analyze(path, burst_minutes=minutes)["bursts"]


class BurstTests(unittest.TestCase):
    def test_a_tight_run_is_one_incident(self):
        events = [alert(ts=f"2026-10-05T09:0{m}:00Z") for m in range(5)]
        b = run(events, 5)
        self.assertEqual((b["alerts_with_timestamp"], b["incidents"], b["reduction_percent"]), (5, 1, 80.0))

    def test_a_gap_longer_than_the_window_starts_a_new_incident(self):
        b = run([alert(ts="2026-10-05T09:00:00Z"), alert(ts="2026-10-05T09:03:00Z"), alert(ts="2026-10-05T09:20:00Z")], 5)
        self.assertEqual(b["incidents"], 2)

    def test_different_rules_and_agents_never_merge(self):
        b = run([alert(rid="1"), alert(rid="2"), alert(rid="1", agent="002")], 5)
        self.assertEqual(b["incidents"], 3)
        self.assertEqual(b["reduction_percent"], 0)

    def test_out_of_order_alerts_inside_the_window_still_join(self):
        b = run([alert(ts="2026-10-05T09:04:00Z"), alert(ts="2026-10-05T09:01:00Z"), alert(ts="2026-10-05T09:02:00Z")], 5)
        self.assertEqual(b["incidents"], 1)

    def test_alerts_without_a_timestamp_are_skipped_and_counted(self):
        b = run([alert(ts=None), alert(ts="garbage"), alert()], 5)
        self.assertEqual((b["alerts_with_timestamp"], b["alerts_skipped_without_timestamp"], b["incidents"]), (1, 2, 1))

    def test_no_flag_means_no_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text(json.dumps(alert()), encoding="utf-8")
            self.assertNotIn("bursts", analyze(path))

    def test_the_report_names_no_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text("\n".join(json.dumps(alert(agent="secret-agent-77")) for _ in range(3)), encoding="utf-8")
            report = analyze(path, burst_minutes=5)
        self.assertNotIn("secret-agent-77", json.dumps(report))
        self.assertNotIn("secret-agent-77", views.html_report(report))

    def test_html_and_markdown_show_the_burst_view(self):
        events = [alert(ts=f"2026-10-05T09:0{m}:00Z") for m in range(4)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
            report = analyze(path, burst_minutes=5)
        self.assertIn("How repetitive is it?", views.html_report(report))
        self.assertIn("Burst view (5 minute window)", views.markdown_report(report))

    def test_cli_validates_the_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text(json.dumps(alert()), encoding="utf-8")
            out = str(Path(tmp) / "r.json")
            for bad in ("0", "-5", "5000"):
                self.assertEqual(main([str(path), "--json", out, "--burst-window", bad]), 2, bad)
            self.assertEqual(main([str(path), "--json", out, "--burst-window", "5"]), 0)


if __name__ == "__main__":
    unittest.main()
