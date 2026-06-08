"""Generates small synthetic pcap fixtures used by the test suite.

Real malicious captures (see ../../samples/README.md) are great for a
human demo, but they are large, change over time, and aren't suitable
to vendor into a repo or CI. These synthetic captures give the test
suite small, deterministic, fast inputs that exercise each detector's
positive and negative paths.

Run directly to (re)write the fixtures:
    venv/Scripts/python.exe tests/fixtures/generate.py
"""

from __future__ import annotations

import random
from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

FIXTURES_DIR = Path(__file__).parent
BASE_TIME = 1_700_000_000.0


def _stamp(packets, start=BASE_TIME, step=0.05):
    """Assign monotonically increasing timestamps (scapy defaults to 'now')."""
    t = start
    for pkt in packets:
        pkt.time = t
        t += step
    return packets


def normal_traffic():
    """A handful of ordinary client/server exchanges — should yield zero findings."""
    pkts = []
    client, server = "10.0.0.10", "93.184.216.34"
    for i, port in enumerate([443, 443, 443, 80]):
        pkts.append(Ether() / IP(src=client, dst=server) /
                    TCP(sport=40000 + i, dport=port, flags="S"))
        pkts.append(Ether() / IP(src=server, dst=client) /
                    TCP(sport=port, dport=40000 + i, flags="SA"))
        pkts.append(Ether() / IP(src=client, dst=server) /
                    TCP(sport=40000 + i, dport=port, flags="A"))
    for name in ["www.example.com", "api.example.com", "cdn.example.com"]:
        pkts.append(Ether() / IP(src=client, dst="8.8.8.8") /
                    UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)))
    return _stamp(pkts)


def port_scan_traffic():
    """One host SYN-scanning ~30 ports on a target within a couple of seconds."""
    attacker, target = "10.0.0.66", "10.0.0.5"
    pkts = []
    for port in range(20, 50):
        pkts.append(Ether() / IP(src=attacker, dst=target) /
                    TCP(sport=51000, dport=port, flags="S"))
    return _stamp(pkts, step=0.05)


def stealth_scan_traffic():
    """NULL and XMAS scan packets from one attacker against one target."""
    attacker, target = "10.0.0.77", "10.0.0.6"
    pkts = []
    for port in range(1000, 1006):
        pkts.append(Ether() / IP(src=attacker, dst=target) / TCP(sport=52000, dport=port, flags=0))
    for port in range(2000, 2006):
        pkts.append(Ether() / IP(src=attacker, dst=target) /
                    TCP(sport=52001, dport=port, flags="FPU"))
    return _stamp(pkts, step=0.1)


def dns_tunneling_traffic():
    """Long, high-entropy single-label TXT queries — mirrors real tunnels
    (iodine/dnscat2) that cram a base32/64-encoded payload chunk into one
    subdomain label rather than spreading it across multiple labels."""
    client = "10.0.0.20"
    # Simulate base32-encoded payload chunks: uniformly random picks from a
    # 32-symbol alphabet, which is what real tunneling tools (iodine,
    # dnscat2) produce and yields the high per-character entropy that
    # distinguishes them from ordinary hostnames.
    rng = random.Random(1337)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    blobs = ["".join(rng.choices(alphabet, k=32)) for _ in range(8)]
    pkts = []
    for i, blob in enumerate(blobs * 3):
        qname = f"{blob}.{i:04x}.exfil-tunnel.example"
        pkts.append(Ether() / IP(src=client, dst="8.8.8.8") /
                    UDP(sport=53000 + i, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT")))
    return _stamp(pkts, step=0.2)


def arp_spoofing_traffic():
    """Two different MACs claiming the same gateway IP — cache-poisoning signature."""
    gateway_ip = "10.0.0.1"
    real_mac, attacker_mac = "aa:aa:aa:aa:aa:aa", "de:ad:be:ef:00:01"
    victim_mac = "bb:bb:bb:bb:bb:bb"
    pkts = []
    for _ in range(3):
        pkts.append(Ether(src=real_mac) / ARP(op=2, psrc=gateway_ip, hwsrc=real_mac,
                                               pdst=gateway_ip, hwdst=victim_mac))
    for _ in range(4):
        pkts.append(Ether(src=attacker_mac) / ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac,
                                                   pdst=gateway_ip, hwdst=victim_mac))
    return _stamp(pkts, step=0.5)


FIXTURES = {
    "normal.pcap": normal_traffic,
    "port_scan.pcap": port_scan_traffic,
    "stealth_scan.pcap": stealth_scan_traffic,
    "dns_tunneling.pcap": dns_tunneling_traffic,
    "arp_spoofing.pcap": arp_spoofing_traffic,
}


def write_all():
    for filename, builder in FIXTURES.items():
        path = FIXTURES_DIR / filename
        wrpcap(str(path), builder())
        print(f"wrote {path}")


if __name__ == "__main__":
    write_all()
