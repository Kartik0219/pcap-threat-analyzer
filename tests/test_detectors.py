"""End-to-end detector tests against small synthetic pcap fixtures.

Each fixture is purpose-built (see fixtures/generate.py) to contain
exactly one suspicious pattern plus, in normal.pcap's case, none at all.
This lets us assert both that real signals are caught (no false
negatives on the obvious cases) and that benign traffic stays quiet
(no false positives).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_analyzer.engine import analyze

FIXTURES = Path(__file__).parent / "fixtures"


def _pcap(name: str) -> str:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"fixture {name} missing — run tests/fixtures/generate.py")
    return str(path)


def test_normal_traffic_produces_no_findings():
    findings = analyze(_pcap("normal.pcap"))
    assert findings == []


def test_port_scan_is_detected():
    findings = analyze(_pcap("port_scan.pcap"), enabled=["port_scan"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector == "port_scan"
    assert finding.src_ip == "10.0.0.66"
    assert finding.evidence["distinct_targets"] >= 15


def test_port_scan_threshold_is_configurable():
    # Raise the bar above what the fixture contains -> no finding.
    findings = analyze(_pcap("port_scan.pcap"), enabled=["port_scan"], port_threshold=100)
    assert findings == []


def test_stealth_scans_are_detected():
    findings = analyze(_pcap("stealth_scan.pcap"), enabled=["tcp_flags"])
    assert len(findings) == 2
    signatures = {f.evidence["signature"] for f in findings}
    assert any("NULL" in s for s in signatures)
    assert any("XMAS" in s for s in signatures)
    assert all(f.src_ip == "10.0.0.77" for f in findings)


def test_dns_tunneling_is_detected():
    findings = analyze(_pcap("dns_tunneling.pcap"), enabled=["dns_tunneling"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.src_ip == "10.0.0.20"
    assert "exfil-tunnel.example" in finding.dst_ip
    assert finding.confidence in {"medium", "high"}
    assert finding.evidence["avg_label_entropy"] > 3.0


def test_arp_spoofing_is_detected():
    findings = analyze(_pcap("arp_spoofing.pcap"), enabled=["arp_spoofing"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.src_ip == "10.0.0.1"
    assert len(finding.evidence["conflicting_macs"]) == 2
    assert "aa:aa:aa:aa:aa:aa" in finding.evidence["conflicting_macs"]
    assert "de:ad:be:ef:00:01" in finding.evidence["conflicting_macs"]


def test_findings_are_sorted_chronologically():
    findings = analyze(_pcap("port_scan.pcap"))
    timestamps = [f.first_seen for f in findings]
    assert timestamps == sorted(timestamps)


def test_unknown_detector_name_raises():
    with pytest.raises(ValueError, match="Unknown detector"):
        analyze(_pcap("normal.pcap"), enabled=["not_a_real_detector"])


def test_running_a_subset_only_invokes_those_detectors():
    findings = analyze(_pcap("port_scan.pcap"), enabled=["dns_tunneling", "arp_spoofing"])
    assert findings == []
