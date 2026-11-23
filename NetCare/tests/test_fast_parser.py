"""빠른 해석 경로(fast_record)가 Scapy 경로(parse_packet)와 같은 레코드를 만드는지, 못 하는 패킷은 넘기는지 확인."""
import socket
import struct

import scapy.all  # noqa: F401  (실시간 캡처와 같은 계층 바인딩)
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, Dot1Q, Ether, Loopback
from scapy.packet import Raw

from netcare.capture.capstats import RawFrame
from netcare.capture.parser import fast_record, parse_packet
from tests.tls_builders import chrome_hello, record

ME, MAC = "192.168.7.10", "02:00:00:00:07:10"
E_IN = dict(src="02:00:00:00:00:01", dst=MAC)


def both(p, link="ether", local=ME):
    data = bytes(p)
    cls = Ether if link == "ether" else Loopback
    r1 = fast_record(data, 1_700_000_000.5, {local}, {MAC}, link=link)
    r2 = parse_packet(RawFrame(cls, data, 1_700_000_000.5).dissect(), {local}, {MAC})
    return r1, r2


def same(p, **kw):
    r1, r2 = both(p, **kw)
    assert r1 is not None, "빠른 경로가 처리해야 하는 패킷"
    assert r1 == r2, {k: (r1.get(k), r2.get(k)) for k in set(r1) | set(r2) if r1.get(k) != r2.get(k)}
    return r1


def skipped(p, **kw):
    r1, _ = both(p, **kw)
    assert r1 is None


def test_common_tcp_udp_are_identical():
    same(Ether(**E_IN) / IP(src="203.0.113.5", dst=ME, ttl=52) / TCP(sport=443, dport=50000, flags="PA", seq=7, ack=9) / Raw(b"\x17\x03\x03" + b"z" * 300))
    same(Ether(src=MAC, dst="02:00:00:00:00:01") / IP(src=ME, dst="203.0.113.5") / TCP(sport=50000, dport=443, flags="S",
         options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 2)), ("WScale", 7)]))
    same(Ether(**E_IN) / IP(src="203.0.113.5", dst=ME) / TCP(sport=443, dport=50001, flags="A"))            # 짧은 프레임 → 채움 바이트
    same(Ether(**E_IN) / IP(src="198.51.100.1", dst=ME) / UDP(sport=443, dport=51000) / Raw(b"\xc3" + b"q" * 1200))   # QUIC 형태
    same(Ether(**E_IN) / IP(src="198.51.100.1", dst=ME) / UDP(sport=40000, dport=40002) /
         Raw(struct.pack("!BBHII", 0x80, 0, 5, 800, 0xABCD) + b"\x00" * 160))                                # RTP
    same(Ether(**E_IN) / IP(src="198.51.100.1", dst=ME, options=b"\x01\x01\x01\x00") / TCP(sport=80, dport=50002) / Raw(b"hi"))


def test_payload_parsers_identical_tls_http_ftp():
    r = same(Ether(src=MAC, dst="02:00:00:00:00:01") / IP(src=ME, dst="203.0.113.9") / TCP(sport=50003, dport=443, flags="PA") /
             Raw(record(chrome_hello("fast.example"))))
    assert r["tls"] and r["tls"].get("sni") == "fast.example"
    same(Ether(src=MAC, dst="02:00:00:00:00:01") / IP(src=ME, dst="203.0.113.9") / TCP(sport=50004, dport=8080, flags="PA") /
         Raw(b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"))
    same(Ether(**E_IN) / IP(src="203.0.113.9", dst=ME) / TCP(sport=21, dport=50005, flags="PA") / Raw(b"530 Login incorrect.\r\n"))


def test_ipv6_igmp_and_checksum_identical():
    same(Ether(**E_IN, type=0x86DD) / IPv6(src="2001:db8::1", dst="2001:db8::10") / TCP(sport=443, dport=50006, flags="SA"), local="2001:db8::10")
    same(Ether(**E_IN, type=0x86DD) / IPv6(src="2001:db8::1", dst="2001:db8::10") / UDP(sport=443, dport=50007) / Raw(b"v6"), local="2001:db8::10")
    # 실제 IGMP 처럼 Router Alert 옵션 포함 → 두 경로 같음
    same(Ether(**E_IN) / IP(src="192.168.7.1", dst="224.0.0.1", proto=2, ttl=1, options=b"\x94\x04\x00\x00") / Raw(b"\x11\x64\xee\x9b\x00\x00\x00\x00"))
    # Router Alert 가 없는 IGMP: Scapy 는 다시 조립하며 없는 옵션 4바이트를 붙여 길이를 46으로 적는다. 빠른 경로는 실제 42바이트
    r1, r2 = both(Ether(**E_IN) / IP(src="192.168.7.1", dst="224.0.0.1", proto=2) / Raw(b"\x11\x64\xee\x9b\x00\x00\x00\x00"))
    assert r1["length"] == 42 and r2["length"] == 46 and {k for k in r1 if r1[k] != r2[k]} == {"length", "raw"}
    bad = bytearray(bytes(Ether(**E_IN) / IP(src="203.0.113.5", dst=ME) / UDP(sport=5000, dport=6000, chksum=0x1234) / Raw(b"x" * 20)))
    r = same(Ether(bytes(bad)))
    assert r["csum"]["l4"] is False


def test_loopback_identical():
    same(Loopback(type=2) / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=50000, dport=47999) / Raw(b"N" * 120), link="null", local="127.0.0.1")
    same(Loopback(type=socket.AF_INET6) / IPv6(src="::1", dst="::1") / TCP(sport=50001, dport=8765, flags="S"), link="null", local="::1")


def test_cases_left_to_scapy():
    skipped(Ether(**E_IN) / IP(src="8.8.8.8", dst=ME) / UDP(sport=53, dport=50000) / DNS(id=1, qr=1, qd=DNSQR(qname="a.example")))   # DNS 포트
    skipped(Ether(**E_IN) / IP(src="8.8.8.8", dst=ME, flags="MF") / UDP(sport=1, dport=2) / Raw(b"x" * 40))                         # 조각
    skipped(Ether(**E_IN) / IP(src="8.8.8.8", dst=ME, frag=10) / Raw(b"x" * 40))
    skipped(Ether(**E_IN) / Dot1Q(vlan=5) / IP(src="8.8.8.8", dst=ME) / TCP())                                                        # VLAN
    skipped(Ether(**E_IN) / IPv6(src="2001:db8::1", dst="2001:db8::10") / IPv6ExtHdrHopByHop() / UDP())                               # 확장 헤더
    skipped(Ether(**E_IN) / IP(src="8.8.8.8", dst=ME) / ICMP(type=3, code=3) / IP(src=ME, dst="8.8.8.8") / UDP(sport=1, dport=2))     # ICMP 오류
    skipped(Ether(**E_IN) / ARP(psrc="192.168.7.1", pdst=ME))
    skipped(Ether(**E_IN) / IP(src="8.8.8.8", dst=ME) / UDP(sport=4789, dport=4789) / Raw(b"\x08" + b"\x00" * 30))                  # VXLAN 포트(터널)
    assert fast_record(b"\x00" * 20, 0.0) is None                                                                                      # 잘린 프레임
    skipped(Ether(**E_IN) / IP(src="8.8.8.8", dst=ME) / UDP(sport=1000, dport=2000, len=4) / Raw(b"x"))                             # 잘못된 UDP 길이


def test_engine_live_path_uses_fast_record_with_same_result(tmp_path):
    from netcare.capture.engine import Engine
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    eng = Engine(ConfigStore(tmp_path / "c.json"), Database(tmp_path / "t.db"), run_probe=False)
    try:
        eng._begin("pcap", None, None, "t", local_ips={ME}, local_macs={MAC})
        p = Ether(**E_IN) / IP(src="203.0.113.5", dst=ME) / TCP(sport=443, dport=50000, flags="PA") / Raw(b"\x17\x03\x03" + b"d" * 50)
        r_live = eng._handle_packet(RawFrame(Ether, bytes(p), 1_700_000_000.0), "live")
        q = Ether(bytes(p))
        q.time = 1_700_000_000.0
        r_pk = eng._handle_packet(q, "live")
        for k in ("src", "dst", "proto", "sport", "dport", "flags", "payload_len", "info", "friendly", "raw", "direction"):
            assert r_live[k] == r_pk[k], k
    finally:
        eng.shutdown()
