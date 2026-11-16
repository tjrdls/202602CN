"""가상 네트워크 모델 (Simulation Lab 전용).

여기서 만드는 패킷은 **절대 네트워크로 전송되지 않는다.** Scapy 객체를 메모리에서 만들어
실험실 전용 Engine 의 큐에만 넣는다. 이 모듈은 send/sendp/sr 같은 전송 함수를 import 하지 않는다.

관찰 지점(vantage): '내 컴퓨터' = CLIENT(10.77.0.10). NetCare 가 이 장치의 인터페이스를 캡처한다고 가정한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, UDPerror, IPerror
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

# ── 가상 장치 (사설 대역 10.77.0.0/24 + 문서용 예제 대역만 사용) ──
CLIENT_IP, CLIENT_MAC = "10.77.0.10", "02:77:00:00:00:10"
GW_IP, GW_MAC = "10.77.0.1", "02:77:00:00:00:01"
DNS_IP, DNS_MAC = "10.77.0.53", "02:77:00:00:00:53"
DOT_IP = "10.77.0.54"                       # 조치용 '신뢰 DNS(암호화, TCP 853)'
SERVER_IP, SERVER_MAC = "10.77.0.20", "02:77:00:00:00:20"   # 사내/집 서버(NAS 등)
ATTACKER_IP, ATTACKER_MAC = "10.77.0.66", "02:77:00:00:00:66"
EXT_ATTACKER = "203.0.113.50"
SITES = {"192.0.2.10": ("news.example", 22.0), "192.0.2.20": ("shop.example", 28.0), "192.0.2.30": ("video.example", 25.0)}
STREAM_SERVER = "192.0.2.30"
FAKE_IP = "203.0.113.66"                    # DNS 위조 응답이 가리키는 가짜 서버
LAB_SUBNET = "10.77.0.0/24"


def mac_of(ip: str) -> str:
    """같은 LAN 장치면 그 장치 MAC, 외부 주소면 게이트웨이 MAC (라우터를 거쳐 들어옴)."""
    return {CLIENT_IP: CLIENT_MAC, GW_IP: GW_MAC, DNS_IP: DNS_MAC, SERVER_IP: SERVER_MAC, ATTACKER_IP: ATTACKER_MAC,
            DOT_IP: GW_MAC}.get(ip, GW_MAC)


def to_client(src_ip: str, l4, ttl: int = 56, src_mac: str | None = None):
    return Ether(src=src_mac or mac_of(src_ip), dst=CLIENT_MAC) / IP(src=src_ip, dst=CLIENT_IP, ttl=ttl) / l4


def from_client(dst_ip: str, l4, dst_mac: str | None = None):
    return Ether(src=CLIENT_MAC, dst=dst_mac or mac_of(dst_ip)) / IP(src=CLIENT_IP, dst=dst_ip, ttl=64) / l4


def tls_data(n: int) -> Raw:
    n = max(6, n)
    return Raw(b"\x17\x03\x03" + (n - 5).to_bytes(2, "big") + bytes(n - 5))


def dns_query(qid: int, sport: int, name: str, server: str = DNS_IP, qtype: str = "A"):
    return from_client(server, UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype)))


def dns_answer(qid: int, sport: int, name: str, ip: str | None, server: str = DNS_IP, rcode: int = 0, src_mac: str | None = None):
    an = DNSRR(rrname=name, type="A", rdata=ip, ttl=300) if (ip and rcode == 0) else []
    return to_client(server, UDP(sport=53, dport=sport) / DNS(id=qid, qr=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=an),
                     ttl=64, src_mac=src_mac)


def arp_reply(claim_ip: str, claim_mac: str, to_ip: str = CLIENT_IP, to_mac: str = CLIENT_MAC, sender_mac: str | None = None):
    return Ether(src=sender_mac or claim_mac, dst=to_mac) / ARP(op=2, psrc=claim_ip, hwsrc=claim_mac, pdst=to_ip, hwdst=to_mac)


def arp_request(target_ip: str):
    return Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=CLIENT_IP, hwsrc=CLIENT_MAC, pdst=target_ip)


def icmp_port_unreachable(to_ip: str, orig_sport: int, orig_dport: int):
    return from_client(to_ip, ICMP(type=3, code=3) / IPerror(src=to_ip, dst=CLIENT_IP) / UDPerror(sport=orig_sport, dport=orig_dport))


@dataclass
class Effects:
    """가상 대응 조치의 상태. 생성기가 매 초 이 값을 보고 패킷을 만든다 (실제 시스템과 무관)."""
    host_blocked: set = field(default_factory=set)   # 내 컴퓨터 방화벽(가상): 들어오는 패킷은 캡처되지만 응답하지 않음
    static_arp: bool = False                         # 공유기 MAC 고정: 위조 ARP 를 무시
    trusted_dns: bool = False                        # 암호화 DNS(DoT)로 전환: 평문 DNS 질의 중단
    ingress_filter: bool = False                     # 공유기 인그레스 필터링(가상): 위조 출발지 패킷이 LAN 에 들어오지 못함
    fault_cleared: bool = False                      # 실험 제어: 장애 주입 종료 (NetCare 조치가 아님)
    log: list = field(default_factory=list)          # (초, 조치)
