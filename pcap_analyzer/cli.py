"""Command-line interface for the PCAP threat analyzer."""

from __future__ import annotations

import argparse
import sys

from . import report
from .detectors import DETECTORS
from .engine import analyze


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap-analyzer",
        description="Analyze a PCAP file for suspicious network activity "
                    "(port scans, stealth scans, DNS tunneling, ARP spoofing).",
    )
    parser.add_argument("pcap", help="Path to a .pcap or .pcapng capture file")
    parser.add_argument(
        "--checks", nargs="+", choices=sorted(DETECTORS.keys()), metavar="CHECK",
        help="Run only these detectors (default: run all). "
             f"Choices: {', '.join(sorted(DETECTORS.keys()))}",
    )
    parser.add_argument("--csv", metavar="PATH", help="Write findings to a CSV file")
    parser.add_argument("--html", metavar="PATH", help="Write findings to an HTML report")
    parser.add_argument(
        "--port-scan-window", type=int, default=10,
        help="Rolling time window (seconds) used by the port-scan detector (default: 10)",
    )
    parser.add_argument(
        "--port-scan-threshold", type=int, default=15,
        help="Distinct (host, port) pairs within the window that trigger a finding (default: 15)",
    )
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress the console table (useful with --csv/--html)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        findings = analyze(
            args.pcap,
            enabled=args.checks,
            window_seconds=args.port_scan_window,
            port_threshold=args.port_scan_threshold,
        )
    except FileNotFoundError:
        parser.error(f"capture file not found: {args.pcap}")
    except OSError as exc:
        parser.error(f"could not read capture file: {exc}")

    if not args.quiet:
        print(report.to_console(findings))

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            fh.write(report.to_csv(findings))
        print(f"\nCSV report written to {args.csv}", file=sys.stderr)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.to_html(findings, pcap_path=args.pcap))
        print(f"HTML report written to {args.html}", file=sys.stderr)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
