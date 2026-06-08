"""Renders findings as a console table, CSV, or standalone HTML report."""

from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timezone

from .models import Finding

CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (CONFIDENCE_ORDER.get(f.confidence, 9), f.first_seen))


def to_console(findings: list[Finding]) -> str:
    if not findings:
        return "No suspicious activity detected."

    rows = _sorted(findings)
    headers = ["Confidence", "Category", "Source", "Destination", "First Seen", "Summary"]
    table = [headers]
    for f in rows:
        table.append([
            f.confidence.upper(),
            f.category,
            f.src_ip,
            f.dst_ip,
            _fmt_ts(f.first_seen),
            f.summary,
        ])

    widths = [max(len(str(row[i])) for row in table) for i in range(len(headers))]
    lines = []
    for i, row in enumerate(table):
        line = " | ".join(str(cell).ljust(widths[j]) for j, cell in enumerate(row))
        lines.append(line)
        if i == 0:
            lines.append("-+-".join("-" * w for w in widths))

    summary = f"\n{len(findings)} finding(s) - " + ", ".join(
        f"{sum(1 for f in findings if f.confidence == level)} {level}"
        for level in ("high", "medium", "low")
    )
    return "\n".join(lines) + summary


def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["confidence", "category", "detector", "src_ip", "dst_ip",
                     "first_seen", "last_seen", "summary", "evidence"])
    for f in _sorted(findings):
        writer.writerow([
            f.confidence, f.category, f.detector, f.src_ip, f.dst_ip,
            _fmt_ts(f.first_seen), _fmt_ts(f.last_seen), f.summary, f.evidence,
        ])
    return buf.getvalue()


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PCAP Threat Analysis Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1b1f23; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #57606a; margin-bottom: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #d0d7de; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }}
  th {{ background: #f6f8fa; }}
  tr.high {{ background: #ffeef0; }}
  tr.medium {{ background: #fff8e6; }}
  tr.low {{ background: #f6f8fa; }}
  .badge {{ font-weight: 600; padding: 0.1rem 0.5rem; border-radius: 0.3rem; }}
  .badge.high {{ background: #cf222e; color: white; }}
  .badge.medium {{ background: #9a6700; color: white; }}
  .badge.low {{ background: #57606a; color: white; }}
  code {{ font-size: 0.85em; }}
</style>
</head>
<body>
  <h1>PCAP Threat Analysis Report</h1>
  <p class="meta">Source capture: <code>{pcap_path}</code> &middot; Generated {generated} &middot; {summary}</p>
  <table>
    <thead>
      <tr><th>Confidence</th><th>Category</th><th>Source</th><th>Destination</th>
          <th>First Seen</th><th>Last Seen</th><th>Summary</th><th>Evidence</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""


def to_html(findings: list[Finding], pcap_path: str = "") -> str:
    rows = _sorted(findings)
    summary = ", ".join(
        f"{sum(1 for f in findings if f.confidence == level)} {level}"
        for level in ("high", "medium", "low")
    ) + f" ({len(findings)} total)" if findings else "No findings"

    body_rows = []
    for f in rows:
        evidence = "<br>".join(f"<code>{html.escape(k)}</code>: {html.escape(str(v))}"
                               for k, v in f.evidence.items())
        body_rows.append(
            f'<tr class="{f.confidence}">'
            f'<td><span class="badge {f.confidence}">{f.confidence.upper()}</span></td>'
            f'<td>{html.escape(f.category)}</td>'
            f'<td>{html.escape(f.src_ip)}</td>'
            f'<td>{html.escape(f.dst_ip)}</td>'
            f'<td>{_fmt_ts(f.first_seen)}</td>'
            f'<td>{_fmt_ts(f.last_seen)}</td>'
            f'<td>{html.escape(f.summary)}</td>'
            f'<td>{evidence}</td>'
            f'</tr>'
        )
    if not body_rows:
        body_rows.append('<tr><td colspan="8">No suspicious activity detected.</td></tr>')

    return _HTML_TEMPLATE.format(
        pcap_path=html.escape(pcap_path),
        generated=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary=summary,
        rows="\n      ".join(body_rows),
    )
