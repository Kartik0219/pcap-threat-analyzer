"""Detection of abnormal TCP flag combinations associated with stealth
scanning techniques (NULL, FIN, XMAS scans).

A normal TCP handshake always starts with a SYN. Packets that arrive
with no flags, only FIN, or FIN+PSH+URG set are not part of any normal
connection lifecycle and are a strong scanning signal (nmap -sN/-sF/-sX).
"""

from __future__ import annotations

from collections import defaultdict

from scapy.layers.inet import IP, TCP

from ..models import Finding

# Bitmasks for the flags we care about (ignore ECE/CWR/NS).
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
RELEVANT_MASK = FIN | SYN | RST | PSH | ACK | URG

SCAN_SIGNATURES = {
    0x00: "NULL scan (no flags set)",
    FIN: "FIN scan (FIN only)",
    FIN | PSH | URG: "XMAS scan (FIN+PSH+URG)",
}

MIN_PACKETS_TO_FLAG = 3


def detect(packets) -> list[Finding]:
    hits: dict[tuple[str, str, int], dict] = defaultdict(
        lambda: {"count": 0, "first": None, "last": None, "ports": set()}
    )

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        flags = int(pkt[TCP].flags) & RELEVANT_MASK
        if flags not in SCAN_SIGNATURES:
            continue

        ip = pkt[IP]
        key = (ip.src, ip.dst, flags)
        bucket = hits[key]
        ts = float(pkt.time)
        bucket["count"] += 1
        bucket["ports"].add(int(pkt[TCP].dport))
        bucket["first"] = ts if bucket["first"] is None else min(bucket["first"], ts)
        bucket["last"] = ts if bucket["last"] is None else max(bucket["last"], ts)

    findings: list[Finding] = []
    for (src, dst, flags), bucket in hits.items():
        if bucket["count"] < MIN_PACKETS_TO_FLAG:
            continue
        signature = SCAN_SIGNATURES[flags]
        confidence = "high" if bucket["count"] >= MIN_PACKETS_TO_FLAG * 3 else "medium"
        findings.append(Finding(
            detector="tcp_flags",
            category="Stealth Scan",
            confidence=confidence,
            src_ip=src,
            dst_ip=dst,
            summary=(
                f"{src} sent {bucket['count']} packets to {dst} matching "
                f"{signature} across {len(bucket['ports'])} ports"
            ),
            first_seen=bucket["first"],
            last_seen=bucket["last"],
            evidence={
                "signature": signature,
                "packet_count": bucket["count"],
                "ports_sample": sorted(bucket["ports"])[:30],
            },
        ))

    return findings
