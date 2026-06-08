"""ARP spoofing / cache-poisoning detection.

Core heuristic: in a healthy network each IP address should resolve to
exactly one MAC address. If we observe the same sender IP advertised
from two or more different MAC addresses, that is the textbook signature
of ARP cache poisoning (e.g. arpspoof, ettercap). Gratuitous ARP replies
(sender IP == target IP) are recorded as supporting evidence since
attackers commonly use them to push poisoned mappings.
"""

from __future__ import annotations

from collections import defaultdict

from scapy.layers.l2 import ARP

from ..models import Finding

ARP_REPLY = 2
MIN_CONFLICTING_OBSERVATIONS = 2


def detect(packets) -> list[Finding]:
    # ip -> {mac -> [timestamps]}
    ip_to_macs: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    gratuitous: dict[tuple[str, str], int] = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer(ARP):
            continue
        arp = pkt[ARP]
        ts = float(pkt.time)
        sender_ip, sender_mac = arp.psrc, arp.hwsrc

        if sender_ip and sender_mac:
            ip_to_macs[sender_ip][sender_mac].append(ts)

        if arp.op == ARP_REPLY and arp.psrc == arp.pdst:
            gratuitous[(sender_ip, sender_mac)] += 1

    findings: list[Finding] = []
    for ip, macs in ip_to_macs.items():
        if len(macs) < 2:
            continue
        total_observations = sum(len(ts) for ts in macs.values())
        if total_observations < MIN_CONFLICTING_OBSERVATIONS:
            continue

        all_ts = [t for ts in macs.values() for t in ts]
        mac_list = sorted(macs.keys())
        confidence = "high" if len(macs) > 2 or any(
            (ip, mac) in gratuitous for mac in macs
        ) else "medium"

        findings.append(Finding(
            detector="arp_spoofing",
            category="ARP Spoofing",
            confidence=confidence,
            src_ip=ip,
            dst_ip="(broadcast/lan)",
            summary=(
                f"IP {ip} was advertised by {len(macs)} different MAC addresses "
                f"({', '.join(mac_list)}) - possible ARP cache poisoning"
            ),
            first_seen=min(all_ts),
            last_seen=max(all_ts),
            evidence={
                "conflicting_macs": mac_list,
                "observations_per_mac": {m: len(ts) for m, ts in macs.items()},
                "gratuitous_arp_seen": any((ip, mac) in gratuitous for mac in macs),
            },
        ))

    return findings
