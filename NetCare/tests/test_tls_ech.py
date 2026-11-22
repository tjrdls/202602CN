"""TLS ClientHello 의 SNI·ECH·ESNI 판정 테스트.

ECH(Encrypted Client Hello)를 쓰면 바깥 ClientHello 의 SNI 는 공개 이름이고 진짜 도메인은 암호화된다.
NetCare 는 진짜 도메인을 복호화하지 않으며, 공개 이름을 실제 목적지로 단정하지 않아야 한다.
"""
import struct

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from netcare.capture.parser import client_hello_info, dissect, parse_packet, parse_tls


def _ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def _sni_ext(name: str) -> bytes:
    n = name.encode()
    entry = b"\x00" + struct.pack("!H", len(n)) + n          # host_name(0) + 길이 + 이름
    return _ext(0x0000, struct.pack("!H", len(entry)) + entry)


def client_hello(*exts: bytes) -> bytes:
    """TLS 레코드(Handshake) 안의 ClientHello 바이트를 만든다."""
    body = b"\x03\x03" + b"\x11" * 32                         # legacy_version + random
    body += b"\x00"                                            # session id 길이 0
    body += struct.pack("!H", 2) + b"\x13\x01"                 # cipher suites
    body += b"\x01\x00"                                        # compression methods
    ext = b"".join(exts)
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body     # handshake type 1 + 3바이트 길이
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs   # record: handshake, TLS 1.0 표기


ECH_BODY = b"\x00" + b"\x00\x01\x00\x01" + b"\x07" + b"\x00\x20" + b"\xaa" * 32 + b"\x00\x40" + b"\xbb" * 64


def _pkt(payload: bytes):
    p = Ether(src="02:00:00:00:00:aa", dst="02:00:00:00:00:bb") / IP(src="192.168.0.10", dst="203.0.113.5") / TCP(sport=50000, dport=443, flags="PA") / Raw(payload)
    return p.__class__(bytes(p))


def test_plain_sni():
    t = parse_tls(client_hello(_sni_ext("github.com")))
    assert t["sni"] == "github.com" and "ech" not in t and "esni" not in t
    rec = parse_packet(_pkt(client_hello(_sni_ext("github.com"))), {"192.168.0.10"})
    assert "SNI=github.com" in rec["info"] and "ECH" not in rec["info"]
    assert rec["friendly"].startswith("github.com 사이트에")


def test_ech_with_public_name_is_not_reported_as_destination():
    raw = client_hello(_sni_ext("cloudflare-ech.com"), _ext(0xFE0D, ECH_BODY))
    t = parse_tls(raw)
    assert t["ech"] is True and t["ech_status"] == "public_name"
    rec = parse_packet(_pkt(raw), {"192.168.0.10"})
    assert "ECH 사용" in rec["info"] and "공개 이름=cloudflare-ech.com" in rec["info"]
    assert "cloudflare-ech.com" not in rec["friendly"] and "숨겨져" in rec["friendly"]
    d = dissect(bytes(_pkt(raw)), "Ether")
    fields = {f["name"]: f for layer in d["layers"] for f in layer["fields"]}
    assert "실제 도메인 아님" in fields["tls.sni"]["label"]
    assert "실제 ECH 사용" in fields["tls.ech_status"]["value"]


def test_ech_extension_with_ordinary_name_is_marked_uncertain():
    """브라우저는 ECH 를 안 쓸 때도 가짜(GREASE) ECH 를 붙인다 → 실제 ECH 인지 확정하지 않는다."""
    raw = client_hello(_sni_ext("www.google.com"), _ext(0xFE0D, ECH_BODY))
    t = parse_tls(raw)
    assert t["sni"] == "www.google.com" and t["ech_status"] == "present"
    rec = parse_packet(_pkt(raw), {"192.168.0.10"})
    assert "SNI=www.google.com" in rec["info"] and "ECH 확장 있음" in rec["info"]
    d = dissect(bytes(_pkt(raw)), "Ether")
    fields = {f["name"]: f for layer in d["layers"] for f in layer["fields"]}
    assert "확정 불가" in fields["tls.ech_status"]["value"] and "GREASE" in fields["tls.ech"]["desc"]


def test_esni_without_plain_sni():
    raw = client_hello(_ext(0xFFCE, b"\x13\x01" + b"\xcc" * 40))
    t = parse_tls(raw)
    assert t.get("esni") is True and "sni" not in t
    rec = parse_packet(_pkt(raw), {"192.168.0.10"})
    assert "ESNI 사용" in rec["info"] and "숨겨져" in rec["friendly"]


def test_truncated_client_hello_does_not_crash():
    raw = client_hello(_sni_ext("example.com"), _ext(0xFE0D, ECH_BODY))
    for cut in (6, 20, 45, 60, len(raw) - 10):
        info = client_hello_info(raw[5:cut])
        assert set(info) == {"sni", "ech", "esni"}
