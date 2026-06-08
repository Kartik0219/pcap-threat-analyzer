# PCAP Threat Analyzer

A command-line tool that scans network packet captures (PCAP/PCAPNG)
for common signs of malicious activity and produces clear, shareable
reports — built to demonstrate practical network-security analysis
skills (PCAP/protocol knowledge, detection-logic design, and tooling).

```
$ python -m pcap_analyzer.cli capture.pcap

Confidence | Category      | Source      | Destination | First Seen              | Summary
-----------+---------------+-------------+-------------+-------------------------+----------------------------------------------------------------
HIGH       | Port Scan     | 10.0.0.66   | 10.0.0.5    | 2023-11-14 22:13:20 UTC | 10.0.0.66 touched 30 distinct (host, port) pairs within 10s - likely a port scan
HIGH       | DNS Tunneling | 10.0.0.20   | exfil...    | 2023-11-14 22:13:20 UTC | 10.0.0.20 sent 24 unusual DNS queries for *.exfil-tunnel.example (...)

2 finding(s) - 2 high, 0 medium, 0 low
```

## What it detects

| Detector | Signal | Why it matters |
|---|---|---|
| **Port scan** | One source touching ≥ N distinct (host, port) pairs within a rolling time window | Classic horizontal/vertical reconnaissance signature (nmap, masscan) |
| **Stealth scans** | TCP packets with NULL, FIN-only, or FIN+PSH+URG ("XMAS") flag combinations | These never occur in a normal TCP lifecycle — a strong nmap `-sN`/`-sF`/`-sX` indicator |
| **DNS tunneling** | Long/high-entropy subdomain labels, heavy TXT/NULL/CNAME usage, high query volume to one domain | Common technique for C2 and data exfiltration over DNS (iodine, dnscat2) |
| **ARP spoofing** | One IP address advertised by multiple MAC addresses, optionally with gratuitous ARP replies | Textbook ARP cache-poisoning / MITM signature (arpspoof, ettercap) |

Each finding includes a confidence rating (`low`/`medium`/`high`) and
structured evidence (counts, sample ports, conflicting MACs, etc.) so
you can verify *why* something was flagged rather than taking the tool's
word for it.

## Installation

```bash
git clone <this-repo>
cd pcap-threat-analyzer
python -m venv venv
# Windows: venv\Scripts\activate   |   macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

Requires Python 3.10+ and [Scapy](https://scapy.net/) (installed via
`requirements.txt`). No `tshark`/Wireshark install is required — Scapy
parses pcap files natively.

## Usage

```bash
# Run every detector and print a console report
python -m pcap_analyzer.cli capture.pcap

# Run specific detectors only
python -m pcap_analyzer.cli capture.pcap --checks port_scan tcp_flags

# Export machine-readable / shareable reports
python -m pcap_analyzer.cli capture.pcap --csv findings.csv --html report.html

# Tune the port-scan heuristic for noisier or quieter networks
python -m pcap_analyzer.cli capture.pcap --port-scan-window 30 --port-scan-threshold 25
```

Run `python -m pcap_analyzer.cli --help` for the full option list. The
process exits with status `1` if any findings were produced and `0` if
the capture looked clean — handy for scripting/CI checks.

## How it's built

```
pcap_analyzer/
├── parser.py            # Streams packets out of a pcap via Scapy's PcapReader
├── engine.py            # Loads a capture once, fans it out to every detector
├── models.py            # Finding dataclass shared by all detectors/reports
├── detectors/
│   ├── port_scan.py     # Rolling-window distinct (host, port) counter
│   ├── tcp_flags.py     # NULL / FIN / XMAS flag-combination matcher
│   ├── dns_tunneling.py # Multi-signal scoring: length, entropy, query type, volume
│   └── arp_spoofing.py  # IP→MAC mapping-conflict tracker + gratuitous-ARP check
├── report.py            # Console table, CSV, and self-contained HTML renderers
└── cli.py               # argparse front-end
```

The capture is parsed exactly once (`engine.analyze`) and the in-memory
packet list is shared across all detectors, so adding a new check is as
simple as dropping a module with a `detect(packets) -> list[Finding]`
function into `detectors/` and registering it in `detectors/__init__.py`.

## Testing

The test suite uses small, deterministic **synthetic** captures
(`tests/fixtures/generate.py`) rather than vendoring large real-world
PCAPs — each fixture is purpose-built to contain exactly one suspicious
pattern (or none, for the "normal traffic" baseline), so the tests
assert both that real signals are caught and that benign traffic stays
quiet.

```bash
pip install -r requirements-dev.txt
pytest
```

To regenerate the fixtures after changing detection logic or adding new
scenarios:

```bash
python tests/fixtures/generate.py
```

`samples/README.md` lists public sources of **real** malicious captures
(Malware-Traffic-Analysis.net, Stratosphere IPS, the Wireshark wiki) for
manual demos and write-ups — they're intentionally not part of the
automated suite since they're large and not ours to redistribute.

## Design notes & limitations

- **Heuristic, not signature-based.** Every detector uses statistical
  thresholds (port counts per window, query entropy, etc.) tuned against
  the synthetic fixtures and sanity-checked against public captures.
  Real-world traffic is messier — expect to tune `--port-scan-window`/
  `--port-scan-threshold` (and the constants at the top of each detector
  module) for your environment, and treat `low`/`medium` findings as
  leads to investigate rather than verdicts.
- **DNS tunneling detection deliberately requires multiple signals to
  agree** (length *and* entropy *and*/*or* record-type mix *and*/*or*
  volume) before raising a finding, since CDNs and some SaaS platforms
  also produce long, odd-looking hostnames on their own.
- **Single-pass, in-memory.** Captures are loaded fully into memory once
  per run. This keeps the architecture simple and is fine for the
  exercise-sized captures (tens of MB) typical of a portfolio demo; very
  large captures would need a streaming/chunked redesign.

## Ethical use

This tool only **reads** existing capture files — it does not capture
live traffic, send packets, or interact with any network. Only run it
against captures you are authorized to analyze (your own lab traffic,
or publicly published research/exercise datasets such as those listed
in `samples/README.md`).
