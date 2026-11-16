"""[테스트 데이터] 시나리오 패킷 생성기.

여기서 만드는 패킷은 실제 네트워크로 전송되지 않는다. 메모리에서 만든 Scapy 패킷을
NetCare 처리 파이프라인에만 넣으며, 모든 레코드에 source='test' 가 붙어 화면에
'테스트 데이터' 배지로 표시되고 리포트에서는 기본적으로 제외된다.

IP 는 문서/예제용으로 예약된 대역(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)과
가상의 사설 주소(192.168.77.0/24)만 사용한다.
"""
from __future__ import annotations

import random
from typing import Iterator

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

LOCAL_IP = "192.168.77.10"
LOCAL_MAC = "02:00:00:00:77:10"
GW_IP = "192.168.77.1"
GW_MAC = "02:00:00:00:77:01"
DNS_IP = GW_IP

WEB = ["192.0.2.10", "192.0.2.20", "192.0.2.30"]
SITES = {"192.0.2.10": "news.example", "192.0.2.20": "shop.example", "192.0.2.30": "video.example"}

SCENARIOS = {
    "normal": {"title": "평상시 웹 사용", "desc": "DNS 조회, HTTPS 접속, 핑 등 평범한 사용 패턴 (이상 징후 없음이 정상)", "duration": 20},
    "syn_flood": {"title": "SYN Flood (연결 요청 폭주)", "desc": "외부 장치가 내 컴퓨터 80번 포트로 응답을 끝맺지 않는 연결 요청을 대량 전송", "duration": 20},
    "port_scan": {"title": "포트 스캔", "desc": "외부 장치가 내 컴퓨터의 여러 포트를 차례로 두드림", "duration": 20},
    "dns_failure": {"title": "DNS 장애", "desc": "DNS 서버가 오류를 돌려주거나 응답하지 않음", "duration": 20},
    "traffic_surge": {"title": "트래픽 급증", "desc": "대용량 다운로드로 사용량이 갑자기 증가 (오탐 완화 동작 확인용)", "duration": 20},
}


def _eth(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)


def _up(dst_ip, l4):
    return _eth(LOCAL_MAC, GW_MAC) / IP(src=LOCAL_IP, dst=dst_ip, ttl=64) / l4


def _down(src_ip, l4, ttl=56):
    return _eth(GW_MAC, LOCAL_MAC) / IP(src=src_ip, dst=LOCAL_IP, ttl=ttl) / l4


def _dns_pair(rng: random.Random, name: str, ip: str, rcode: int = 0, answer: bool = True):
    qid = rng.randint(1, 65535)
    sport = rng.randint(49152, 65535)
    q = _up(DNS_IP, UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
    if not answer:
        return [q]
    an = DNSRR(rrname=name, type="A", rdata=ip, ttl=300) if rcode == 0 else []
    r = _down(DNS_IP, UDP(sport=53, dport=sport) / DNS(id=qid, qr=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=an), ttl=64)
    return [q, r]


def _https_session(rng: random.Random, server: str, n_data: int = 6):
    sp = rng.randint(49152, 65535)
    seq, sseq = rng.randint(1, 2**31), rng.randint(1, 2**31)
    pk = [
        _up(server, TCP(sport=sp, dport=443, flags="S", seq=seq, window=65535)),
        _down(server, TCP(sport=443, dport=sp, flags="SA", seq=sseq, ack=seq + 1, window=65160)),
        _up(server, TCP(sport=sp, dport=443, flags="A", seq=seq + 1, ack=sseq + 1, window=2058)),
        _up(server, TCP(sport=sp, dport=443, flags="PA", seq=seq + 1, ack=sseq + 1) / Raw(b"\x17\x03\x03\x00\x40" + bytes(64))),
    ]
    for i in range(n_data):
        pk.append(_down(server, TCP(sport=443, dport=sp, flags="PA", seq=sseq + 1 + i * 1200, ack=seq + 70) / Raw(b"\x17\x03\x03\x04\xab" + bytes(1195))))
        pk.append(_up(server, TCP(sport=sp, dport=443, flags="A", seq=seq + 70, ack=sseq + 1 + (i + 1) * 1200)))
    return pk


def _background(rng: random.Random) -> list:
    """1초 분량의 평범한 트래픽."""
    pk = []
    srv = rng.choice(WEB)
    if rng.random() < 0.5:
        pk += _dns_pair(rng, SITES[srv], srv)
    pk += _https_session(rng, srv, rng.randint(2, 8))
    if rng.random() < 0.2:
        pk.append(_up(GW_IP, ICMP(type=8, id=1, seq=rng.randint(1, 999))))
        pk.append(_down(GW_IP, ICMP(type=0, id=1, seq=1), ttl=64))
    return pk


def generate(name: str, seed: int = 7) -> Iterator[tuple[int, list]]:
    """(초 오프셋, 그 초에 보낼 패킷 목록)을 차례로 내놓는다."""
    if name not in SCENARIOS:
        raise ValueError(f"알 수 없는 시나리오: {name}")
    rng = random.Random(seed)
    dur = SCENARIOS[name]["duration"]
    for sec in range(dur):
        pk = _background(rng)
        attack = 4 <= sec < 16
        if name == "syn_flood" and attack:
            attacker = "203.0.113.50"
            for _ in range(250):
                sp = rng.randint(1024, 65535)
                s = rng.randint(1, 2**31)
                pk.append(_down(attacker, TCP(sport=sp, dport=80, flags="S", seq=s, window=1024), ttl=48))
                # 내 컴퓨터는 SYN-ACK 로 응답하지만 공격자는 마지막 ACK 를 보내지 않는다
                pk.append(_up(attacker, TCP(sport=80, dport=sp, flags="SA", seq=rng.randint(1, 2**31), ack=s + 1)))
        elif name == "port_scan" and 4 <= sec < 10:
            scanner = "198.51.100.23"
            for port in range((sec - 4) * 40 + 1, (sec - 3) * 40 + 1):
                sp = rng.randint(40000, 60000)
                pk.append(_down(scanner, TCP(sport=sp, dport=port, flags="S", seq=rng.randint(1, 2**31), window=1024), ttl=50))
                pk.append(_up(scanner, TCP(sport=port, dport=sp, flags="RA", seq=0, ack=1)))
        elif name == "dns_failure" and attack:
            for i in range(4):
                host = rng.choice(["mail.example", "cloud.example", "news.example", "api.example"])
                if i % 2 == 0:
                    pk += _dns_pair(rng, host, "", rcode=2)  # SERVFAIL
                else:
                    pk += _dns_pair(rng, host, "", answer=False)  # 무응답
        elif name == "traffic_surge" and 6 <= sec < 14:
            server = "192.0.2.30"
            sp = 51515
            base = rng.randint(1, 2**31)
            for i in range(8000):
                pk.append(_down(server, TCP(sport=443, dport=sp, flags="A", seq=base + i * 1400, ack=1) / Raw(b"\x17\x03\x03\x05\x73" + bytes(1395))))
                if i % 4 == 0:  # 수신 확인(ACK) — 양방향 통신
                    pk.append(_up(server, TCP(sport=sp, dport=443, flags="A", seq=1, ack=base + (i + 1) * 1400)))
        yield sec, pk
