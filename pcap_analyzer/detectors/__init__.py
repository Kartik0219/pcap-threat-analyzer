"""Detection modules. Each exposes a `detect(packets) -> list[Finding]` function."""

from . import arp_spoofing, dns_tunneling, port_scan, tcp_flags

DETECTORS = {
    "port_scan": port_scan,
    "tcp_flags": tcp_flags,
    "dns_tunneling": dns_tunneling,
    "arp_spoofing": arp_spoofing,
}
