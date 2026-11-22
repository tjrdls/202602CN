# UDP Packet Manipulation and Defense Socket Project

Computer Networks course project on reproducing UDP packet manipulation and implementing a defensive socket server.

## NetCare (implementation)

The [`NetCare/`](NetCare/) folder contains **NetCare**, a beginner-friendly real-time network packet analysis and troubleshooting system with a built-in virtual attack lab (Simulation Lab).
See [NetCare/README.md](NetCare/README.md) (Korean) for how it works, the system architecture, the 22 detection rules, and the attack lab.

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
