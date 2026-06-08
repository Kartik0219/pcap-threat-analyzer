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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PCAP Threat Analysis Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
    background: #f5f5f7;
    margin: 0;
    padding: 2.5rem 1.5rem 5rem;
    color: #1d1d1f;
    -webkit-font-smoothing: antialiased;
  }}
  .container {{ max-width: 1040px; margin: 0 auto; }}
  h1 {{
    font-size: 2.2rem;
    font-weight: 700;
    letter-spacing: -0.025em;
    margin: 0 0 0.4rem;
  }}
  .meta {{
    font-size: 0.88rem;
    color: #6e6e73;
    margin: 0 0 2rem;
  }}
  .card {{
    background: #fff;
    border-radius: 18px;
    box-shadow: 0 2px 14px rgba(0,0,0,.06);
    overflow: hidden;
  }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.88rem; }}
  th {{
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #6e6e73;
    padding: 0.85rem 1.25rem;
    text-align: left;
    background: #fafafa;
    border-bottom: 1px solid #f0f0f0;
    white-space: nowrap;
  }}
  td {{
    padding: 0.85rem 1.25rem;
    border-bottom: 1px solid #f5f5f7;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr.high   {{ background: rgba(255,103,0,.045); }}
  tr.medium {{ background: rgba(255,149,0,.045); }}
  tr.low    {{ background: transparent; }}
  .badge {{
    display: inline-block;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    padding: 0.22rem 0.65rem;
    border-radius: 20px;
    color: #fff;
    white-space: nowrap;
  }}
  .badge.high   {{ background: #ff6700; }}
  .badge.medium {{ background: #ff9500; }}
  .badge.low    {{ background: #34c759; }}
  code {{
    font-family: "SF Mono", Menlo, Monaco, Consolas, monospace;
    font-size: 0.82em;
    background: #f5f5f7;
    padding: 0.1em 0.4em;
    border-radius: 5px;
  }}
</style>
</head>
<body>
<div class="container">
  <h1>PCAP Threat Analysis Report</h1>
  <p class="meta">Source capture: <code>{pcap_path}</code> &middot; Generated {generated} &middot; {summary}</p>
  <div class="card">
    <table>
      <thead>
        <tr><th>Confidence</th><th>Category</th><th>Source</th><th>Destination</th>
            <th>First Seen</th><th>Last Seen</th><th>Summary</th><th>Evidence</th></tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</div>
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
