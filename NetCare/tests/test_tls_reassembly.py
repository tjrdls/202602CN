"""ClientHello 완전 해석과 TCP 재조립 테스트."""
import random

from netcare.encrypted import CONFIRMED, ESTIMATED, FAILED, LIMITED
from netcare.encrypted.reassembly import TcpReassembler
from netcare.encrypted.tls_hello import is_grease, parse_client_hello, parse_server_hello, sni_view
from tests.tls_builders import chrome_hello, client_hello, groups, record, server_hello, sni, versions

KEY = ("10.0.0.2", 51000, "203.0.113.5", 443)
ISN = 4_000_000_000          # 순서 번호가 2^32 를 넘어 한 바퀴 도는 경우도 함께 시험


def segments(data: bytes, size: int = 1448, start: int = ISN + 1):
    return [((start + i) % (1 << 32), data[i:i + size]) for i in range(0, len(data), size)]


def test_parse_modern_client_hello():
    ch = parse_client_hello(chrome_hello("www.example.com"))
    assert ch["complete"] and ch["error"] is None
    assert ch["tls_version"] == "TLS 1.3" and ch["legacy_version"] == "TLS 1.2"
    assert ch["sni"] == "www.example.com" and ch["alpn"] == ["h2", "http/1.1"]
    assert ch["groups"][:2] == ["X25519MLKEM768", "x25519"] and "X25519MLKEM768" in ch["pqc"]
    assert ch["hybrid"] and [k["group"] for k in ch["key_share"]] == ["X25519MLKEM768", "x25519"]
    assert ch["ech"] and ch["ech_type"] == "outer"
    assert all(not g.startswith("0x") for g in ch["groups"])          # GREASE 제외
    assert is_grease(0x1A1A) and not is_grease(0x11EC)


def test_sni_view_separates_observed_real_outer():
    plain = sni_view(parse_client_hello(client_hello(sni("a.example"), versions(0x0304))))
    assert plain["status"] == CONFIRMED and plain["real_sni"] == "a.example" and plain["outer_sni"] is None
    grease = sni_view(parse_client_hello(chrome_hello("b.example", ech=True)))
    assert grease["status"] == ESTIMATED and grease["observed_sni"] == "b.example" and grease["real_sni"] is None
    ech = sni_view(parse_client_hello(chrome_hello("secret.example", public_name="cloudflare-ech.com")))
    assert ech["status"] == LIMITED and ech["outer_sni"] == "cloudflare-ech.com" and ech["real_sni"] is None
    assert "secret" not in str(ech)                                   # 실제 도메인을 추측해 넣지 않음
    nosni = sni_view(parse_client_hello(client_hello(groups(0x001D))))
    assert nosni["status"] == LIMITED and nosni["observed_sni"] is None


def test_server_hello_shows_negotiated_hybrid_group():
    sh = parse_server_hello(server_hello())
    assert sh["tls_version"] == "TLS 1.3" and sh["group"] == "X25519MLKEM768" and sh["hybrid"] and not sh["hrr"]


def test_reassembly_in_order_split_hello():
    data = record(chrome_hello("split.example"))
    assert len(data) > 1500
    r = TcpReassembler()
    r.syn(KEY, ISN, 0.0, want=1)
    res = None
    for seq, d in segments(data):
        res = r.feed(KEY, seq, d, 0.1) or res
    assert res["status"] == "complete" and res["multi_segment"] and res["hello"]["sni"] == "split.example"
    assert r.stats["complete_multi"] == 1 and not r.streams


def test_reassembly_out_of_order_duplicates_and_overlap():
    data = record(chrome_hello("shuffle.example"))
    segs = segments(data, size=300)
    rng = random.Random(3)
    feed = segs[:] + [segs[2], segs[5]]                               # 재전송(중복)
    o_seq, o_d = segs[3]
    feed.append(((o_seq + 100) % (1 << 32), o_d[100:] + segs[4][1][:50]))   # 다른 세그먼트와 일부 겹침
    rng.shuffle(feed)
    r = TcpReassembler()
    r.syn(KEY, ISN, 0.0, want=1)
    res = [x for x in (r.feed(KEY, s, d, 0.2) for s, d in feed) if x]
    assert len(res) == 1 and res[0]["status"] == "complete" and res[0]["hello"]["sni"] == "shuffle.example"
    assert res[0]["reordered"] >= 1 and res[0]["conflicts"] == 0


def test_conflicting_overlap_is_counted():
    data = record(chrome_hello("conflict.example"))
    segs = segments(data, size=500)
    r = TcpReassembler()
    r.syn(KEY, ISN, 0.0, want=1)
    r.feed(KEY, *segs[0], 0.1)
    s1, d1 = segs[1]
    r.feed(KEY, s1, b"X" * len(d1), 0.1)                              # 다른 내용이 먼저 도착 (주입·우회 시도 형태)
    out = [x for x in (r.feed(KEY, s, d, 0.2) for s, d in segs[1:]) if x]
    assert out and out[0]["conflicts"] >= 1


def test_missing_segment_fails_with_reason():
    data = record(chrome_hello("gap.example"))
    segs = segments(data, size=600)
    r = TcpReassembler()
    r.syn(KEY, ISN, 0.0, want=1)
    for s, d in segs[:1] + segs[2:]:                                  # 두 번째 세그먼트 누락
        assert r.feed(KEY, s, d, 1.0) is None
    fails = r.expire(10.0)
    assert fails and fails[0]["status"] == "failed" and fails[0]["code"] == "gap_timeout" and "빠진" in fails[0]["reason"]
    r2 = TcpReassembler()
    r2.syn(KEY, ISN, 0.0, want=1)
    r2.feed(KEY, *segs[0], 0.1)
    res = r2.feed(KEY, (segs[-1][0] + len(segs[-1][1])) % (1 << 32), b"", 0.2, fin=True)
    assert res["code"] == "closed" and r2.fail_reasons == {"closed": 1}


def test_mid_stream_without_syn_and_non_tls_ignored():
    data = record(chrome_hello("nosyn.example"))
    segs = segments(data)
    r = TcpReassembler()
    assert r.feed(KEY, segs[1][0], segs[1][1], 0.0) is None            # 두 번째 조각이 먼저 (SYN 없음)
    res = r.feed(KEY, segs[0][0], segs[0][1], 0.1)
    assert res and res["hello"]["sni"] == "nosyn.example"
    assert r.feed(("a", 1, "b", 2), 1, b"GET / HTTP/1.1\r\n\r\n", 0.0) is None and not r.streams


def test_memory_bounds():
    r = TcpReassembler(max_streams=50)
    head = record(chrome_hello("m.example"))[:200]
    for i in range(200):
        r.feed(("10.0.0.2", 10000 + i, "203.0.113.5", 443), 1000, head, 0.0)
    assert len(r.streams) == 50 and r.stats["evicted"] == 150


def test_server_hello_reassembly():
    data = record(server_hello(key_bytes=1120))
    r = TcpReassembler()
    key = ("203.0.113.5", 443, "10.0.0.2", 51000)
    r.syn(key, 77, 0.0, want=2)
    res = [x for x in (r.feed(key, s, d, 0.1, want=2) for s, d in segments(data, size=700, start=78)) if x]
    assert res[0]["hello"]["group"] == "X25519MLKEM768" and res[0]["hello"]["hybrid"]


def test_truncated_and_garbage_never_raise():
    full = chrome_hello("t.example")
    for cut in (1, 5, 40, 80, 200, len(full) - 3):
        ch = parse_client_hello(full[:cut])
        assert isinstance(ch, dict)
    assert parse_client_hello(b"\x02abc")["error"] and parse_server_hello(b"")["error"]
    assert sni_view(parse_client_hello(full[:60]))["status"] in (FAILED, LIMITED)


def test_mid_connection_handshake_record_is_not_a_failure():
    """캡처 전에 열린 연결에서 ClientHello 가 아닌 핸드셰이크 레코드(예: TLS 1.2 재협상)가 보이면 실패가 아니라 대상 아님."""
    r = TcpReassembler()
    rec = b"\x16\x03\x03\x00\x10" + b"\x10" + b"\x00\x00\x0c" + b"\x00" * 12   # ClientKeyExchange
    assert r.feed(KEY, 5000, rec, 0.0) is None and r.stats["failed"] == 0 and not r.streams
