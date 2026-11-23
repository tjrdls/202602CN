# UDP Packet Manipulation and Defense Socket Project

Computer Networks course project on reproducing UDP packet manipulation and implementing a defensive socket server.

## NetCare (implementation)

The [`NetCare/`](NetCare/) folder contains **NetCare**, a beginner-friendly real-time network packet analysis and troubleshooting system with a built-in virtual attack lab (Simulation Lab).
See [NetCare/README.md](NetCare/README.md) (Korean) for how it works, the system architecture, the 28 detection rules, encrypted-traffic analysis, the attack lab, and all verification results.

Highlights (all numbers are measured; see the linked reports):

- **Detection**: 28 rules, including packet-integrity checks (checksum tampering, TCP injection, UDP replay) and CrowdSec-equivalent web/brute-force scenarios.
- **Public dataset (CSE-CIC-IDS2018)**: 7 of 8 labelled attacks detected (SSH brute force, web login brute force, XSS, SQL injection); the FTP port was closed in the dataset. Real CrowdSec on the same data detected none of the web attacks ([report](NetCare/docs/benchmark/cse-cic-ids2018.md)).
- **Encrypted traffic, without decryption**: TCP reassembly, QUIC Initial (RFC 9001/9369), TLS 1.3, ECH/ESNI, PQC key exchange, and DoT/DoQ/DoH classification. Every result is labelled confirmed, estimated, or limited.
- **Live false positives**: on identical traffic, security alerts dropped from 7 to 0 in one hour after per-connection TTL tracking and state-aware RST checks ([report](NetCare/docs/09_안정성_신뢰성_개선_보고서.md)).
- **Performance and stability**:
  - About 4x processing throughput (24k–27k packets/s on real packets).
  - App, kernel, and NIC drop counters, verified on Linux in CI.
  - Memory bounded at about 44 MB in a 12-hour accelerated soak.

```bash
docker run -d --name netcare -p 127.0.0.1:8765:8765 -v netcare-data:/data ghcr.io/tjrdls/netcare:latest
# then open http://127.0.0.1:8765
```

How the team plan maps to NetCare (observer-side detection, see `NetCare/netcare/detection/integrity.py`):

| Team plan | NetCare |
| --- | --- |
| Spoofing / bit modification / retransmission (Scapy attacks) | IP spoofing rule, `checksum_error` (recomputes IP/TCP/UDP/ICMP checksums of received packets), `udp_replay` |
| UDP server checksum handling | `checksum_error` sees corrupted datagrams that the OS would silently drop |
| Sequence-number validation, duplicate blocking | `udp_replay` (RTP auto-detected, or the team protocol via `udp_seq_ports: ["9999:0:4"]`), `tcp_injection` (per-flow TTL/SEQ checks) |
| Wireshark verification | Packet detail tree + hex dump in NetCare, public dataset benchmark vs CrowdSec (`NetCare/docs/benchmark/`) |

The image is built and published automatically by GitHub Actions (`.github/workflows/netcare-docker.yml`) after the tests pass. To run from source instead: `cd NetCare && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python run.py`.

## Presentation

`UDP_Packet_Defense_Project.pptx` contains the project purpose, UDP concepts, attack packet cases, defense layers, analysis plan, team assignments, and four-week schedule.

## Team assignments

| Member | Responsibility |
| --- | --- |
| 손영준 | Scapy attack packet generation: spoofing, bit modification, retransmission |
| 이석인 | UDP server and checksum handling |
| 이성우 | Sequence-number validation and duplicate blocking |
| 백기현 | Wireshark capture and result verification |
| 이현주 | Integration, report, slides, and presentation |

## Schedule

1. Week 1: Step 1, Scapy packet generation
2. Week 2: Step 2, UDP server implementation
3. Week 3: Step 3, defense and packet analysis
4. Week 4: Integration, presentation, and final tests

The deck distinguishes OS-level UDP checksum handling from application-level sequence checks: a regular UDP socket may never receive a datagram whose checksum the OS rejected.
