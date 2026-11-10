# UDP Packet Manipulation and Defense Socket Project

Computer Networks course project on reproducing UDP packet manipulation and implementing a defensive socket server.

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
