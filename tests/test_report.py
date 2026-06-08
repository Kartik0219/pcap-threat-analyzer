"""Tests for the report rendering layer (console / CSV / HTML)."""

from __future__ import annotations

from pcap_analyzer import report
from pcap_analyzer.models import Finding

SAMPLE = [
    Finding(detector="port_scan", category="Port Scan", confidence="high",
            src_ip="10.0.0.66", dst_ip="10.0.0.5", summary="scanned 30 ports",
            first_seen=1_700_000_000.0, last_seen=1_700_000_005.0,
            evidence={"distinct_targets": 30}),
    Finding(detector="dns_tunneling", category="DNS Tunneling", confidence="medium",
            src_ip="10.0.0.20", dst_ip="exfil-tunnel.example", summary="suspicious DNS volume",
            first_seen=1_700_000_010.0, last_seen=1_700_000_020.0,
            evidence={"query_count": 24}),
]


def test_console_report_lists_all_findings_and_counts():
    text = report.to_console(SAMPLE)
    assert "10.0.0.66" in text
    assert "10.0.0.20" in text
    assert "2 finding(s)" in text
    assert "1 high" in text and "1 medium" in text


def test_console_report_handles_empty_findings():
    assert report.to_console([]) == "No suspicious activity detected."


def test_csv_report_round_trips_core_fields():
    text = report.to_csv(SAMPLE)
    lines = text.strip().splitlines()
    assert lines[0].startswith("confidence,category,detector")
    assert any("10.0.0.66" in line for line in lines)
    assert any("port_scan" in line for line in lines)


def test_html_report_escapes_and_includes_findings():
    text = report.to_html(SAMPLE, pcap_path="capture.pcap")
    assert "<html" in text
    assert "10.0.0.66" in text
    assert "capture.pcap" in text
    assert 'class="badge high"' in text
    assert 'class="badge medium"' in text


def test_html_report_handles_empty_findings():
    text = report.to_html([], pcap_path="capture.pcap")
    assert "No suspicious activity detected." in text
