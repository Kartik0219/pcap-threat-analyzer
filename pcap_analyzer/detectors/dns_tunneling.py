"""DNS tunneling detection.

DNS tunnels encode arbitrary data into subdomain labels to smuggle
traffic past firewalls that allow DNS out. The telltale signs are:
  * unusually long query names / subdomain labels
  * high-entropy (random-looking, often base32/base64) labels
  * a high volume of queries to the same base domain from one host
  * heavy use of record types rarely needed for normal browsing
    (TXT, NULL, CNAME chains)

None of these alone is conclusive (CDNs and some SaaS products produce
long, weird-looking names too) so we score multiple signals and only
raise a finding when several line up.
"""

from __future__ import annotations

import math
from collections import defaultdict

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP

LONG_QNAME_THRESHOLD = 45      # full query name length, in characters
LONG_LABEL_THRESHOLD = 30      # longest single dot-separated label
HIGH_ENTROPY_THRESHOLD = 3.5   # bits/char; English text sits ~3.0-4.0, random b32/b64 data is higher
MIN_QUERIES_TO_SCORE = 8
TUNNEL_PRONE_TYPES = {16, 10, 5}  # TXT=16, NULL=10, CNAME=5


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _base_domain(qname: str) -> str:
    """Best-effort registrable-domain approximation: last two labels."""
    labels = qname.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else qname


def detect(packets):
    from ..models import Finding

    # (src_ip, base_domain) -> stats
    groups: dict[tuple[str, str], dict] = defaultdict(lambda: {
        "queries": [], "types": defaultdict(int), "first": None, "last": None,
    })

    for pkt in packets:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
            continue
        dns = pkt[DNS]
        if dns.qr != 0:  # only count queries, not responses
            continue

        qname = dns[DNSQR].qname.decode(errors="replace") if isinstance(dns[DNSQR].qname, bytes) else str(dns[DNSQR].qname)
        qname = qname.rstrip(".")
        if not qname:
            continue

        base = _base_domain(qname)
        key = (pkt[IP].src, base)
        bucket = groups[key]
        ts = float(pkt.time)
        bucket["queries"].append(qname)
        bucket["types"][int(dns[DNSQR].qtype)] += 1
        bucket["first"] = ts if bucket["first"] is None else min(bucket["first"], ts)
        bucket["last"] = ts if bucket["last"] is None else max(bucket["last"], ts)

    findings = []
    for (src, base), bucket in groups.items():
        queries = bucket["queries"]
        if len(queries) < MIN_QUERIES_TO_SCORE:
            continue

        # For each query, the longest subdomain label is the one most likely
        # to carry an encoded payload chunk — short labels are typically
        # sequence numbers or control fields and would dilute the entropy
        # signal if averaged in indiscriminately.
        payload_labels = []
        for q in queries:
            sub_labels = [lbl for lbl in q.split(".")[:-2] if lbl]
            if sub_labels:
                payload_labels.append(max(sub_labels, key=len))
        if not payload_labels:
            continue

        avg_qname_len = sum(len(q) for q in queries) / len(queries)
        max_label_len = max(len(lbl) for lbl in payload_labels)
        avg_entropy = sum(_shannon_entropy(lbl) for lbl in payload_labels) / len(payload_labels)
        tunnel_type_ratio = sum(
            cnt for t, cnt in bucket["types"].items() if t in TUNNEL_PRONE_TYPES
        ) / len(queries)

        score = 0
        reasons = []
        if avg_qname_len >= LONG_QNAME_THRESHOLD:
            score += 1
            reasons.append(f"avg query name length {avg_qname_len:.0f} chars")
        if max_label_len >= LONG_LABEL_THRESHOLD:
            score += 1
            reasons.append(f"longest subdomain label {max_label_len} chars")
        if avg_entropy >= HIGH_ENTROPY_THRESHOLD:
            score += 1
            reasons.append(f"high label entropy ({avg_entropy:.2f} bits/char)")
        if tunnel_type_ratio >= 0.5:
            score += 1
            reasons.append(f"{tunnel_type_ratio:.0%} of queries use TXT/NULL/CNAME records")
        if len(queries) >= MIN_QUERIES_TO_SCORE * 5:
            score += 1
            reasons.append(f"{len(queries)} queries to the same domain")

        if score < 2:
            continue

        confidence = "high" if score >= 4 else "medium" if score == 3 else "low"
        findings.append(Finding(
            detector="dns_tunneling",
            category="DNS Tunneling",
            confidence=confidence,
            src_ip=src,
            dst_ip=base,
            summary=(
                f"{src} sent {len(queries)} unusual DNS queries for *.{base} "
                f"({'; '.join(reasons)})"
            ),
            first_seen=bucket["first"],
            last_seen=bucket["last"],
            evidence={
                "query_count": len(queries),
                "avg_qname_length": round(avg_qname_len, 1),
                "max_label_length": max_label_len,
                "avg_label_entropy": round(avg_entropy, 2),
                "tunnel_prone_type_ratio": round(tunnel_type_ratio, 2),
                "sample_queries": queries[:5],
            },
        ))

    return findings
