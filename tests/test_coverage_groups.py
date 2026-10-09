import io
import json
from contextlib import redirect_stdout
from datetime import timezone
from pathlib import Path
import tempfile
import unittest

from noiselens import report as views
from noiselens.cli import InputError, analyze, group_by_path, main, parse_timestamp

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def alert(rid="60107", level=4, ts="2026-10-05T09:00:00Z", groups=None, agent="001"):
    a = {"rule": {"id": rid, "level": level}, "agent": {"id": agent}}
    if ts is not None:
        a["timestamp"] = ts
    if groups is not None:
        a["rule"]["groups"] = groups
    return a


def run(tmp, events, *extra):
    path = Path(tmp) / "alerts.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code = main([str(path), "--json", str(Path(tmp) / "r.json"), *extra])
    return code, out.getvalue()


class TimestampTests(unittest.TestCase):
    def test_common_wazuh_and_iso_shapes_are_read_as_utc(self):
        self.assertEqual(parse_timestamp("2026-10-05T09:00:00Z").isoformat(), "2026-10-05T09:00:00+00:00")
        self.assertEqual(parse_timestamp("2026-10-05T09:00:00.123+0000").isoformat(), "2026-10-05T09:00:00.123000+00:00")
        self.assertEqual(parse_timestamp("2026-10-05T14:00:00.5+05:00").isoformat(), "2026-10-05T09:00:00.500000+00:00")
        self.assertEqual(parse_timestamp("2026-10-05T09:00:00Z").tzinfo, timezone.utc)

    def test_garbage_is_none(self):
        for bad in (None, 5, "", "yesterday", "2026-13-45T99:99:99Z", "2026-10-05 09:00:00"):
            self.assertIsNone(parse_timestamp(bad), bad)

    def test_mixed_offsets_are_normalised_before_taking_first_and_last(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text("\n".join(json.dumps(a) for a in [
                alert(ts="2026-10-05T10:00:00+05:00"),   # 05:00 UTC
                alert(ts="2026-10-05T08:00:00Z"),
                alert(ts="2026-10-05T09:00:00+0000"),
                alert(ts=None)]), encoding="utf-8")
            cov = analyze(path)["coverage"]
        self.assertEqual(cov["first_utc"], "2026-10-05T05:00:00+00:00")
        self.assertEqual(cov["last_utc"], "2026-10-05T09:00:00+00:00")
        self.assertEqual(cov["alerts_without_valid_timestamp"], 1)

    def test_no_timestamps_gives_nulls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text(json.dumps(alert(ts=None)), encoding="utf-8")
            cov = analyze(path)["coverage"]
        self.assertIsNone(cov["first_utc"])
        self.assertEqual(cov["alerts_without_valid_timestamp"], 1)


class GroupTests(unittest.TestCase):
    def test_groups_are_counted_once_per_alert_and_ignore_junk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text("\n".join(json.dumps(a) for a in [
                alert(groups=["syscheck", "syscheck", "pci"]), alert(groups=["syscheck"]),
                alert(groups="notalist"), alert(groups=[1, None, "auth"]), alert()]), encoding="utf-8")
            groups = {g["group"]: g["alerts"] for g in analyze(path)["top_groups"]}
        self.assertEqual(groups, {"syscheck": 2, "pci": 1, "auth": 1})

    def test_demo_data_has_groups_and_a_time_range(self):
        report = analyze(EXAMPLES / "alerts.jsonl")
        self.assertEqual({g["group"] for g in report["top_groups"]}, {"windows", "demo_noisy", "demo_protected"})
        self.assertEqual(report["coverage"]["first_utc"], "2026-10-05T09:00:00+00:00")

    def test_html_and_markdown_show_groups_and_coverage_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text(json.dumps(alert(groups=["<b>x</b>|y"])), encoding="utf-8")
            report = analyze(path)
        html = views.html_report(report)
        self.assertIn("Rule groups", html)
        self.assertIn("(UTC)", html)
        self.assertNotIn("<b>x</b>", html)
        self.assertIn(r"\|y", views.markdown_report(report))


class PathDepthTests(unittest.TestCase):
    def test_folds_windows_and_unix_paths(self):
        from collections import Counter
        folded = group_by_path(Counter({r"C:\Tools\a.exe": 3, r"C:\Tools\sub\b.exe": 2, "/var/log/x": 4, "/var/log/y": 1, "plain": 1}), 2)
        self.assertEqual(folded["C:/Tools"], 5)
        self.assertEqual(folded["/var/log"], 5)
        self.assertEqual(folded["plain"], 1)

    def test_breakdown_prints_running_share_and_folds(self):
        events = [{**alert(), "data": {"p": r"C:\Work\x\a.exe"}}] * 3 + [{**alert(), "data": {"p": r"C:\Work\y\b.exe"}}] + [{**alert(), "data": {"p": r"D:\Other\c.exe"}}]
        with tempfile.TemporaryDirectory() as tmp:
            code, out = run(tmp, events, "--breakdown", "60107:data.p", "--path-depth", "2")
        self.assertEqual(code, 0)
        self.assertIn("C:/Work", out)
        self.assertIn("80.0%", out)
        self.assertIn("100.0%", out)

    def test_path_depth_needs_breakdown_and_a_positive_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text(json.dumps(alert()), encoding="utf-8")
            for extra in (["--path-depth", "2"], ["--breakdown", "60107:p", "--path-depth", "0"]):
                self.assertEqual(main([str(path), "--json", str(Path(tmp) / "r.json"), *extra]), 2)


if __name__ == "__main__":
    unittest.main()
