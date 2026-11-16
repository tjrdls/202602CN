"""패킷 파서 단위 테스트 (Scapy 로 만든 패킷 — 네트워크로 전송하지 않음)."""
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from netcare.capture.parser import dissect, parse_packet, parse_tls

LOCAL = {"192.168.0.10"}
MAC = {"aa:aa:aa:aa:aa:aa"}


def client_hello(sni: bytes) -> bytes:
    ext_sni = b"\x00\x00" + (len(sni) + 5).to_bytes(2, "big") + (len(sni) + 3).to_bytes(2, "big") + b"\x00" + len(sni).to_bytes(2, "big") + sni
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(ext_sni).to_bytes(2, "big") + ext_sni
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_tcp_fields_and_direction():
    p = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / IP(src="192.168.0.10", dst="8.8.4.4", ttl=64) / \
        TCP(sport=50000, dport=443, flags="S", seq=1000, window=65535)
    r = parse_packet(p, LOCAL, MAC)
    assert r["proto"] == "TCP" and r["flags"] == "S"
    assert r["sport"] == 50000 and r["dport"] == 443 and r["seq"] == 1000 and r["window"] == 65535
    assert r["ttl"] == 64 and r["src_mac"] == "aa:aa:aa:aa:aa:aa"
    assert r["ethertype"].startswith("0x0800")
    assert r["direction"] == "up"
    assert r["service"] == "HTTPS"
    assert "새로운 연결 요청" in r["friendly"]
    assert r["length"] == len(p)


def test_udp_dns_query_and_response():
    q = Ether() / IP(src="192.168.0.10", dst="192.168.0.1") / UDP(sport=5555, dport=53) / DNS(id=7, qd=DNSQR(qname="example.com"))
    r = parse_packet(q, LOCAL, set())
    assert r["proto"] == "UDP" and r["udp_len"] > 8
    assert r["dns_qname"] == "example.com" and r["dns_qr"] == 0
    a = Ether() / IP(src="192.168.0.1", dst="192.168.0.10") / UDP(sport=53, dport=5555) / \
        DNS(id=7, qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    r2 = parse_packet(a, LOCAL, set())
    assert r2["dns_answers"] == ["93.184.216.34"] and r2["direction"] == "down"
    nx = Ether() / IP(src="192.168.0.1", dst="192.168.0.10") / UDP(sport=53, dport=5555) / DNS(id=8, qr=1, rcode=3, qd=DNSQR(qname="nope.example"))
    assert "실패" in parse_packet(nx, LOCAL, set())["friendly"]


def test_icmp_and_ipv6():
    r = parse_packet(Ether() / IP(src="192.168.0.10", dst="1.1.1.1") / ICMP(type=8), LOCAL, set())
    assert r["proto"] == "ICMP" and r["icmp_type"] == 8
    r6 = parse_packet(Ether() / IPv6(src="fe80::1", dst="2001:db8::1", hlim=33) / UDP(sport=1, dport=53), set(), set())
    assert r6["ip_version"] == 6 and r6["ttl"] == 33


def test_tls_sni_is_plaintext_only():
    payload = client_hello(b"www.example.com")
    t = parse_tls(payload)
    assert t["sni"] == "www.example.com" and t["content_type"] == "Handshake"
    p = Ether() / IP(src="192.168.0.10", dst="1.2.3.4") / TCP(sport=1, dport=443, flags="PA") / Raw(payload)
    r = parse_packet(p, LOCAL, MAC)
    assert r["tls"]["sni"] == "www.example.com"
    app = Ether() / IP() / TCP(sport=443, dport=1, flags="PA") / Raw(b"\x17\x03\x03\x00\x10" + bytes(16))
    d = dissect(bytes(app), "Ether")
    raw_layer = d["layers"][-1]
    assert "복호화" in raw_layer["note"]  # 암호화 데이터는 내용을 보여주지 않음
    assert not any(f["name"] == "preview" for f in raw_layer["fields"])  # 암호문 미리보기도 표시하지 않음


def test_dissect_tree_has_korean_labels():
    p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="SA")
    d = dissect(bytes(p), "Ether")
    names = [l["name"] for l in d["layers"]]
    assert names[:3] == ["Ethernet", "IP", "TCP"]
    tcp = d["layers"][2]
    flags = next(f for f in tcp["fields"] if f["name"] == "flags")
    assert "SYN" in flags["value"] and "ACK" in flags["value"]
    assert any(f["label"].startswith("보내는 장치") for f in d["layers"][1]["fields"])
    assert d["hex"][0]["offset"] == "0000"


def test_garbage_never_raises():
    r = parse_packet(Raw(b"\x00\x01garbage"), set(), set())
    assert r["friendly"]
