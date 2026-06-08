"""CLI smoke tests covering exit codes and report file generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_analyzer.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _pcap(name: str) -> str:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"fixture {name} missing — run tests/fixtures/generate.py")
    return str(path)


def test_main_returns_zero_when_clean(capsys):
    rc = main([_pcap("normal.pcap")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No suspicious activity detected." in out


def test_main_returns_nonzero_when_findings_present(capsys):
    rc = main([_pcap("port_scan.pcap"), "--checks", "port_scan"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "10.0.0.66" in out


def test_main_writes_csv_and_html_reports(tmp_path, capsys):
    csv_path = tmp_path / "report.csv"
    html_path = tmp_path / "report.html"
    rc = main([
        _pcap("port_scan.pcap"), "--checks", "port_scan", "-q",
        "--csv", str(csv_path), "--html", str(html_path),
    ])
    out = capsys.readouterr().out
    assert rc == 1
    assert out == ""  # -q suppresses the console table
    assert csv_path.exists() and "10.0.0.66" in csv_path.read_text(encoding="utf-8")
    assert html_path.exists() and "10.0.0.66" in html_path.read_text(encoding="utf-8")


def test_main_errors_on_missing_file(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["does-not-exist.pcap"])
    assert exc_info.value.code == 2
    assert "capture file not found" in capsys.readouterr().err
