"""Orchestrates loading a pcap once and running every detector against it."""

from __future__ import annotations

from .detectors import DETECTORS
from .models import Finding
from .parser import read_packets


def analyze(pcap_path: str, enabled: list[str] | None = None,
            **detector_kwargs) -> list[Finding]:
    """Run the requested detectors (default: all) against a pcap file.

    Packets are read into memory once and shared across detectors so the
    file is only parsed a single time regardless of how many checks run.
    """
    names = enabled or list(DETECTORS.keys())
    unknown = set(names) - set(DETECTORS.keys())
    if unknown:
        raise ValueError(f"Unknown detector(s): {', '.join(sorted(unknown))}")

    packets = list(read_packets(pcap_path))

    findings: list[Finding] = []
    for name in names:
        module = DETECTORS[name]
        kwargs = {k: v for k, v in detector_kwargs.items()
                  if k in getattr(module.detect, "__code__").co_varnames}
        findings.extend(module.detect(packets, **kwargs))

    findings.sort(key=lambda f: f.first_seen)
    return findings
