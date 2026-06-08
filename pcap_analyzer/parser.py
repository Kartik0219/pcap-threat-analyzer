"""PCAP loading helpers built on top of scapy."""

from __future__ import annotations

from collections.abc import Iterator

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP


def read_packets(pcap_path: str) -> Iterator:
    """Stream packets from a pcap/pcapng file one at a time.

    Using PcapReader (rather than rdpcap) keeps memory usage low for
    large captures since packets are yielded lazily.
    """
    with PcapReader(pcap_path) as reader:
        yield from reader


def has_ip(pkt) -> bool:
    return pkt.haslayer(IP)


def has_tcp(pkt) -> bool:
    return pkt.haslayer(TCP)


def has_udp(pkt) -> bool:
    return pkt.haslayer(UDP)


def has_arp(pkt) -> bool:
    return pkt.haslayer(ARP)


def packet_timestamp(pkt) -> float:
    return float(pkt.time)
