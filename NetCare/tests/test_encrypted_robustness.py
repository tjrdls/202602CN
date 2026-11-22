"""암호화 통신 분석 안정성·오분류 검증 (기능 추가 없음, 검증 전용).

1. 무작위·변형 입력 퍼징: 어떤 바이트가 와도 예외 없이 동작
2. ECH / GREASE 판정 표: 확정할 수 없는 경우 실제 도메인을 채우지 않음
3. DoH 와 일반 HTTPS 오분류: 일반 HTTPS 사이트 30곳이 DoH 로 분류되지 않음
4. DoT·DoQ 분류: 확인/추정 구분
5. 불변식: 분석기 결과 어디에도 '볼 수 없는 정보를 확정'한 값이 없음
"""
import os
import random

from scapy.layers.inet import TCP, UDP

from netcare.encrypted import CONFIRMED, ESTIMATED, LIMITED
from netcare.encrypted.dns_class import DnsClassifier
from netcare.encrypted.quic import V1, QuicAnalyzer
from netcare.encrypted.reassembly import TcpReassembler
from netcare.encrypted.tls_hello import parse_client_hello, parse_server_hello, sni_view
from tests.test_encrypted_analyzer import ME, mk, run, tls_conn
from tests.test_quic import crypto, protect
from tests.tls_builders import alpn, chrome_hello, client_hello, ech_outer, ext, record, server_hello, sni, versions

RNG = random.Random(20261123)


# ───────────── 1. 퍼징 ─────────────
def test_fuzz_random_bytes_never_raise():
    for _ in range(3000):
        b = bytes(RNG.getrandbits(8) for _ in range(RNG.randint(0, 400)))
        parse_client_hello(b"\x01" + b)
        parse_server_hello(b"\x02" + b)
        sni_view(parse_client_hello(b"\x01" + b))
    q = QuicAnalyzer()
    for _ in range(1500):
        n = RNG.randint(1, 1400)
        b = bytes([0xC0 | RNG.getrandbits(6)]) + bytes(RNG.getrandbits(8) for _ in range(n))
        q.datagram(b, 1.0)
    r = TcpReassembler(max_streams=64)
    for i in range(3000):
        key = ("10.0.0.2", 40000 + RNG.randint(0, 300), "203.0.113.5", 443)
        data = (b"\x16\x03\x01" if RNG.random() < 0.3 else b"") + bytes(RNG.getrandbits(8) for _ in range(RNG.randint(0, 600)))
        r.feed(key, RNG.getrandbits(32), data, i * 0.01, fin=RNG.random() < 0.05)
    r.expire(1e9)
    assert len(r.streams) <= 64


def test_bitflip_mutations_of_real_hello_never_raise():
    base = record(chrome_hello("mut.example"))
    for _ in range(2000):
        m = bytearray(base)
        for _ in range(RNG.randint(1, 8)):
            m[RNG.randrange(len(m))] ^= 1 << RNG.randrange(8)
        r = TcpReassembler()
        res = r.feed(("a", 1, "b", 443), 100, bytes(m[:900]), 0.0) or r.feed(("a", 1, "b", 443), 1000, bytes(m[900:]), 0.1)
        if res and res.get("hello"):
            v = sni_view(res["hello"])
            if res["hello"].get("ech"):
                assert v["real_sni"] is None                  # ECH 확장이 남아 있으면 실제 도메인 확정 금지


# ───────────── 2. ECH / GREASE 판정 표 ─────────────
def test_ech_grease_decision_table():
    cases = [
        ("ECH 없음", client_hello(sni("plain.example"), versions(0x0304)), CONFIRMED, "plain.example", None),
        ("GREASE 가능 ECH + 일반 이름", chrome_hello("grease.example", ech=True), ESTIMATED, None, None),
        ("실제 ECH(알려진 공개 이름)", chrome_hello("x", public_name="cloudflare-ech.com"), LIMITED, None, "cloudflare-ech.com"),
        ("실제 ECH(알려진 공개 이름 2)", chrome_hello("x", public_name="public.tls-ech.dev"), LIMITED, None, "public.tls-ech.dev"),
        ("ECH + 모르는 공개 이름 (구분 불가 → 확정하지 않음)", chrome_hello("x", public_name="cover.unknown-ech.net"), ESTIMATED, None, None),
        ("ECH + SNI 없음", client_hello(versions(0x0304), ech_outer()), ESTIMATED, None, None),
        ("inner 표시 ECH 가 평문에 보임", client_hello(sni("odd.example"), ext(0xFE0D, b"\x01")), ESTIMATED, None, None),
    ]
    for name, hs, status, real, outer in cases:
        v = sni_view(parse_client_hello(hs))
        assert (v["status"], v["real_sni"], v["outer_sni"]) == (status, real, outer), name


# ───────────── 3. DoH vs 일반 HTTPS ─────────────
POPULAR = ["www.google.com", "www.youtube.com", "www.naver.com", "www.daum.net", "github.com", "api.github.com", "www.cloudflare.com",
           "cdn.jsdelivr.net", "www.wikipedia.org", "www.apple.com", "www.microsoft.com", "login.microsoftonline.com", "www.amazon.com",
           "www.netflix.com", "www.instagram.com", "www.facebook.com", "x.com", "www.reddit.com", "www.linkedin.com", "www.kakao.com",
           "accounts.google.com", "fonts.googleapis.com", "www.gstatic.com", "s3.amazonaws.com", "www.coupang.com", "news.naver.com",
           "chat.openai.com", "claude.ai", "www.tistory.com", "update.googleapis.com"]


def test_popular_https_sites_are_not_classified_as_doh():
    d = DnsClassifier()
    for i, name in enumerate(POPULAR):
        rec = {"proto": "TCP", "src": ME, "dst": f"203.0.113.{i + 1}", "sport": 50000 + i, "dport": 443, "length": 600, "dns_id": None}
        d.packet(rec, tls=parse_client_hello(client_hello(sni(name), alpn("h2"), versions(0x0304))))
    assert d.snapshot()["flows"]["doh"] == 0


def test_doh_is_only_ever_estimated_with_basis():
    d = DnsClassifier()
    for i, (name, ip) in enumerate([("dns.google", "8.8.8.8"), ("cloudflare-dns.com", "104.16.248.249"), (None, "1.1.1.1"),
                                     ("abc123.dns.nextdns.io", "45.90.28.1")]):
        rec = {"proto": "TCP", "src": ME, "dst": ip, "sport": 51000 + i, "dport": 443, "length": 500, "dns_id": None}
        d.packet(rec, tls=parse_client_hello(client_hello(*([sni(name)] if name else []), alpn("h2"), versions(0x0304))))
    snap = d.snapshot()
    assert snap["flows"]["doh"] == 4 and snap["confirmed_flows"]["doh"] == 0
    assert all(f["basis"] and f["confidence"] in ("높음", "중간") for f in snap["list"] if f["kind"] == "doh")


def test_known_limitation_resolver_website_counts_as_doh_estimate():
    """한계 기록: 1.1.1.1 홈페이지(one.one.one.one) 방문도 DoH '추정'으로 보인다 (확인됨으로는 절대 표시하지 않음)."""
    d = DnsClassifier()
    res = d.packet({"proto": "TCP", "src": ME, "dst": "1.1.1.1", "sport": 52000, "dport": 443, "length": 500, "dns_id": None},
                   tls=parse_client_hello(client_hello(sni("one.one.one.one"), alpn("h2"), versions(0x0304))))
    assert res["kind"] == "doh" and res["status"] == ESTIMATED


# ───────────── 4. DoT · DoQ ─────────────
def test_dot_doq_classification():
    dcid, scid = os.urandom(8), os.urandom(8)
    pk = [mk(ME, "9.9.9.9", TCP(sport=40000, dport=853, flags="S", seq=1), ts=0),                       # TLS 전 → 추정
          mk(ME, "149.112.112.112", TCP(sport=40001, dport=853, flags="PA", seq=1), record(client_hello(sni("dns.quad9.net"), versions(0x0304))), 0.1),
          mk(ME, "94.140.14.14", UDP(sport=41000, dport=853), protect(crypto(0, client_hello(sni("dns.adguard-dns.com"), alpn("doq"), versions(0x0304))), dcid, scid), 0.2),
          mk(ME, "94.140.15.15", UDP(sport=41001, dport=853), b"\x00" * 50, 0.3),                         # QUIC 아님 → 추정
          mk(ME, "203.0.113.70", UDP(sport=41002, dport=443), protect(crypto(0, client_hello(sni("h3.example"), alpn("h3"), versions(0x0304))), os.urandom(8), scid), 0.4)]
    a, _ = run(pk)
    st = {(f["server"], f["kind"]): f["status"] for f in a.dns.flows.values()}
    assert st[("9.9.9.9", "dot")] == ESTIMATED and st[("149.112.112.112", "dot")] == CONFIRMED
    assert st[("94.140.14.14", "doq")] == CONFIRMED and st[("94.140.15.15", "doq")] == ESTIMATED
    assert ("203.0.113.70", "doq") not in st and ("203.0.113.70", "doh") not in st      # 일반 HTTP/3 는 DNS 아님


# ───────────── 5. 불변식: 볼 수 없는 정보를 확정하지 않음 ─────────────
def test_invariants_over_mixed_traffic():
    pk = []
    for i in range(20):
        ech = i % 3 != 0
        pub = "cloudflare-ech.com" if i % 5 == 0 and ech else None
        pk += tls_conn(f"203.0.113.{100 + i}", f"s{i}.example", ech=ech, public_name=pub, cport=52000 + i, t=i, split=i % 2 == 0)
    a, recs = run(pk)
    for e in a.recent(limit=300):
        h, v = e.get("hello") or {}, e.get("sni") or {}
        if h.get("type") == "client_hello" and h.get("ech"):
            assert v.get("real_sni") is None
        if v.get("outer_sni"):
            assert v.get("ech") in ("confirmed", "esni")
    for r in recs:
        if (r.get("enc") or {}).get("sni", {}).get("ech") == "unconfirmed":
            assert "확정할 수 없어요" in r["friendly"]
    assert a.snapshot()["dns"]["confirmed_flows"]["doh"] == 0
