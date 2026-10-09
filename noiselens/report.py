"""Readable HTML and Markdown reports. Everything is escaped, nothing loads remote assets or runs scripts."""
import html

E = html.escape

CSS = (
    ":root{color-scheme:dark}*{box-sizing:border-box}"
    "body{background:#0a0d1a;color:#eee9f7;font:16px/1.55 system-ui,'Segoe UI',sans-serif;max-width:1080px;margin:0 auto;padding:32px 20px 64px}"
    "h1{font-size:30px;margin:0 0 4px;letter-spacing:-.5px}h1 span{color:#ff9f1c}h2{margin:36px 0 12px;font-size:20px}"
    ".sub{color:#b4a7cc;margin:0 0 24px}.cards{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 8px}"
    ".card{background:#151228;border:1px solid #3a2c5a;border-radius:14px;padding:14px 20px;min-width:150px}"
    ".card b{display:block;font-size:30px;line-height:1.1}.card span{color:#b4a7cc;font-size:13px;letter-spacing:.08em;text-transform:uppercase}"
    ".ok{color:#38e0ad}.bad{color:#ff6b87}"
    "table{border-collapse:collapse;width:100%;background:#110f22;border:1px solid #3a2c5a;border-radius:12px;overflow:hidden}"
    "th,td{padding:11px 14px;text-align:left;vertical-align:middle;border-bottom:1px solid #2a2146;font-size:14.5px}"
    "th{background:#1a1632;color:#b4a7cc;font-weight:600;font-size:12.5px;letter-spacing:.07em;text-transform:uppercase}"
    "tr:last-child td{border-bottom:0}code{font:13.5px Consolas,'Cascadia Mono',monospace;color:#ffe3c2}"
    ".bar{height:12px;border-radius:6px;background:#ffffff14;overflow:hidden;display:flex;min-width:140px}"
    ".bar i{display:block;height:100%;background:linear-gradient(90deg,#ff9f1c,#ff3b6b)}.bar i.p{background:#ff2d55}"
    ".verdict{border-radius:12px;padding:14px 18px;margin:18px 0;font-weight:600}"
    ".verdict.fail{background:#ff3b6b24;border:1px solid #ff3b6b88;color:#ffb3c4}.verdict.pass{background:#1fbf8f1f;border:1px solid #1fbf8f77;color:#7ee3bf}"
    ".note{background:#151228;border-left:4px solid #ff9f1c;padding:12px 16px;border-radius:8px;color:#d6cbea;margin:18px 0}"
    "footer{margin-top:40px;color:#8f82a8;font-size:13px}"
)

PAGE = (
    "<!doctype html><html lang='en'><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
    "<title>Wazuh NoiseLens report</title><style>" + CSS + "</style><body>@@BODY@@"
    "<footer>Generated offline by Wazuh NoiseLens. Reports leave out raw logs, descriptions, process paths and agent identifiers. "
    "Volume does not establish false positives, and the numbers describe this dataset only.</footer></body></html>"
)


def _bar(matched, protected, total):
    if not total:
        return "<div class='bar'></div>"
    normal = 100 * (matched - protected) / total
    prot = 100 * protected / total
    return f"<div class='bar'><i style='width:{normal:.2f}%'></i><i class='p' style='width:{prot:.2f}%'></i></div>"


def html_report(report):
    total = report["total_alerts"]
    impact = report.get("impact")
    body = ["<h1><span>Wazuh</span> NoiseLens</h1><p class='sub'>Suppression impact report</p><div class='cards'>"
            f"<div class='card'><b>{total}</b><span>alerts analyzed</span></div>"]
    if impact:
        body.append(
            f"<div class='card'><b>{impact['would_suppress']}</b><span>would be hidden</span></div>"
            f"<div class='card'><b>{impact['remaining']}</b><span>remaining</span></div>"
            f"<div class='card'><b class='{'ok' if impact['protected_would_suppress'] == 0 else 'bad'}'>{impact['protected_would_suppress']}</b><span>of {impact['protected_alerts']} protected hit</span></div>")
    body.append("</div>")
    cov = report.get("coverage") or {}
    if cov.get("first_utc"):
        missing = cov.get("alerts_without_valid_timestamp", 0)
        body.append(f"<p class='sub'>Alerts in this file run from <code>{E(cov['first_utc'])}</code> to <code>{E(cov['last_utc'])}</code> (UTC)"
                    + (f", and {missing} had no readable timestamp" if missing else "") + ".</p>")
    if impact:
        if impact["guard_passed"]:
            body.append("<div class='verdict pass'>No protected alert matched in this dataset. That is not proof the exception is safe on traffic you have not seen.</div>")
        else:
            body.append("<div class='verdict fail'>REVIEW REQUIRED: the proposed policy would hide protected alerts. Check the matching events before you change the manager.</div>")
        body.append("<h2>Proposed suppressions</h2><table><tr><th>Name</th><th>Matches</th><th>Protected matches</th><th>Share of all alerts</th></tr>")
        for s in impact["per_suppression"]:
            body.append(f"<tr><td><code>{E(str(s['name']))}</code></td><td>{s['matches']}</td>"
                        f"<td class='{'bad' if s['protected_matches'] else 'ok'}'>{s['protected_matches']}</td>"
                        f"<td>{_bar(s['matches'], s['protected_matches'], total)}</td></tr>")
        body.append("</table>")
    body.append("<h2>Top rules</h2><table><tr><th>Rule</th><th>Alerts</th><th>Share</th><th>Distinct agents</th></tr>")
    for r in report["top_rules"]:
        body.append(f"<tr><td><code>{E(str(r['rule_id']))}</code></td><td>{r['alerts']}</td>"
                    f"<td>{r['share_percent']}%<br>{_bar(r['alerts'], 0, total)}</td><td>{r['distinct_agents']}</td></tr>")
    body.append("</table>")
    if report.get("top_groups"):
        body.append("<h2>Rule groups</h2><p class='sub'>An alert can belong to several groups, so shares can add up to more than 100%.</p>"
                    "<table><tr><th>Group</th><th>Alerts</th><th>Share</th></tr>")
        for g in report["top_groups"]:
            body.append(f"<tr><td><code>{E(str(g['group']))}</code></td><td>{g['alerts']}</td><td>{g['share_percent']}%<br>{_bar(g['alerts'], 0, total)}</td></tr>")
        body.append("</table>")
    sev = report["severity_distribution"]
    if sev:
        body.append("<h2>Severity</h2><table><tr><th>Level</th><th>Alerts</th><th>Share</th></tr>")
        for level, count in sev.items():
            body.append(f"<tr><td>{E(str(level))}</td><td>{count}</td><td>{_bar(count, 0, total)}</td></tr>")
        body.append("</table>")
    body.append(f"<div class='note'>{E(report['interpretation'])}</div>")
    return PAGE.replace("@@BODY@@", "".join(body))


def _md(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def markdown_report(report):
    total = report["total_alerts"]
    impact = report.get("impact")
    head = f"**{total} alerts analyzed**"
    lines = ["## Wazuh NoiseLens", ""]
    if not impact:
        lines.append(head)
    if impact:
        verdict = "no protected alert matched in this dataset" if impact["guard_passed"] else "REVIEW REQUIRED, protected alerts would be hidden"
        lines += [f"{head} · would hide **{impact['would_suppress']}**, leaves **{impact['remaining']}** · {verdict}", "",
                  "| Suppression | Matches | Protected matches |", "|---|---|---|"]
        lines += [f"| `{_md(s['name'])}` | {s['matches']} | {s['protected_matches']} |" for s in impact["per_suppression"]]
    cov = report.get("coverage") or {}
    if cov.get("first_utc"):
        lines += ["", f"Alerts run from `{cov['first_utc']}` to `{cov['last_utc']}` (UTC)."]
    lines += ["", "| Rule | Alerts | Share | Distinct agents |", "|---|---|---|---|"]
    lines += [f"| `{_md(r['rule_id'])}` | {r['alerts']} | {r['share_percent']}% | {r['distinct_agents']} |" for r in report["top_rules"]]
    if report.get("top_groups"):
        lines += ["", "| Rule group | Alerts | Share |", "|---|---|---|"]
        lines += [f"| `{_md(g['group'])}` | {g['alerts']} | {g['share_percent']}% |" for g in report["top_groups"]]
    lines += ["", f"_{_md(report['interpretation'])}_"]
    return "\n".join(lines) + "\n"


def printable(value, limit=120):
    """A log value made safe to print: no control characters or escape sequences reach the terminal."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"
