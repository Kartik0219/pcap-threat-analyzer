"""Port-scan detection: a single source touching many distinct ports
on one or more destinations within a short time window.

This is the classic "horizontal/vertical scan" signature — legitimate
clients rarely open dozens of distinct destination ports in seconds.
"""

from __future__ import annotations

from collections import defaultdict

from scapy.layers.inet import IP, TCP, UDP

from ..models import Finding

DEFAULT_WINDOW_SECONDS = 10
DEFAULT_PORT_THRESHOLD = 15


def detect(packets, window_seconds: int = DEFAULT_WINDOW_SECONDS,
           port_threshold: int = DEFAULT_PORT_THRESHOLD) -> list[Finding]:
    """Flag sources that contact >= port_threshold distinct ports
    within any rolling window_seconds-second window.

    Approach: bucket (src, dst, port, timestamp) touches per source,
    then slide a window over the sorted timestamps and count distinct
    (dst, port) pairs seen inside it.
    """
    touches: dict[str, list[tuple[float, str, int]]] = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        if pkt.haslayer(TCP):
            dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            dport = int(pkt[UDP].dport)
        else:
            continue
        touches[ip.src].append((float(pkt.time), ip.dst, dport))

    findings: list[Finding] = []
    for src, events in touches.items():
        events.sort(key=lambda e: e[0])
        n = len(events)
        left = 0
        seen_max = 0
        for right in range(n):
            window_start = events[right][0] - window_seconds
            while events[left][0] < window_start:
                left += 1
            window_slice = events[left:right + 1]
            distinct = {(dst, port) for _, dst, port in window_slice}
            if len(distinct) > seen_max:
                seen_max = len(distinct)
                best_slice = window_slice
                best_distinct = distinct

        if seen_max >= port_threshold:
            dsts = sorted({dst for dst, _ in best_distinct})
            ports = sorted({port for _, port in best_distinct})
            confidence = "high" if seen_max >= port_threshold * 2 else "medium"
            findings.append(Finding(
                detector="port_scan",
                category="Port Scan",
                confidence=confidence,
                src_ip=src,
                dst_ip=dsts[0] if len(dsts) == 1 else f"{len(dsts)} hosts",
                summary=(
                    f"{src} touched {seen_max} distinct (host, port) pairs "
                    f"within {window_seconds}s - likely a port scan"
                ),
                first_seen=best_slice[0][0],
                last_seen=best_slice[-1][0],
                evidence={
                    "distinct_targets": seen_max,
                    "destination_hosts": dsts[:20],
                    "destination_ports_sample": ports[:30],
                    "window_seconds": window_seconds,
                },
            ))

    return findings
