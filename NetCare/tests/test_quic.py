"""QUIC Initial 분석 테스트: RFC 테스트 벡터 키, 보호 → 해제 왕복, CRYPTO 재조립, 실패 사유."""
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from netcare.encrypted import CONFIRMED, FAILED, LIMITED
from netcare.encrypted.quic import V1, V2, QuicAnalyzer, _hp_mask, crypto_frames, initial_keys, version_name
from tests.tls_builders import alpn, chrome_hello, client_hello, ext, groups, server_hello, sni, versions


def test_initial_keys_match_rfc9001_appendix_a():
    dcid = bytes.fromhex("8394c8f03e515708")
    c = initial_keys(dcid, V1)
    assert c["key"].hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert c["iv"].hex() == "fa044b2f42a3fd3b46fb255c"
    assert c["hp"].hex() == "9f50449e04a0e810283a1e9933adedd2"
    s = initial_keys(dcid, V1, server=True)
    assert s["key"].hex() == "cf3a5331653c364c88f0f379b6067e37"
    assert s["iv"].hex() == "0ac1493ca1905853b0bba03e"
    assert s["hp"].hex() == "c206b8d9b9f0f37644430b490eeaa314"


def test_initial_keys_match_rfc9369_appendix_a():
    c = initial_keys(bytes.fromhex("8394c8f03e515708"), V2)
    assert c["key"].hex() == "8b1a0bc121284290a29e0971b5cd045d"
    assert c["iv"].hex() == "91f73e2351d8fa91660e909f"
    assert c["hp"].hex() == "45b95e15235d6f45a6b19cbcb0294ba9"


def _vi(n: int) -> bytes:
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack("!H", 0x4000 | n)
    return struct.pack("!I", 0x80000000 | n)


def crypto(off: int, data: bytes) -> bytes:
    return b"\x06" + _vi(off) + _vi(len(data)) + data


def protect(frames: bytes, dcid: bytes, scid: bytes, pn: int = 0, version: int = V1, server: bool = False,
            key_dcid: bytes | None = None, pad_to: int = 1200) -> bytes:
    """테스트용 Initial 패킷 생성 (RFC 9001 5.3·5.4 보호 적용)."""
    keys = initial_keys(key_dcid or dcid, version, server)
    ptype = 1 if version == V2 else 0
    pn_len = 2
    first = 0xC0 | (ptype << 4) | (pn_len - 1)
    pn_bytes = pn.to_bytes(pn_len, "big")
    head = bytes([first]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + _vi(0)
    if not server:
        frames = frames + b"\x00" * max(0, pad_to - len(frames) - len(head) - 4 - 16 - pn_len)
    length = pn_len + len(frames) + 16
    head += struct.pack("!H", 0x4000 | length)
    header = head + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(keys["iv"], pn.to_bytes(12, "big")))
    ct = AESGCM(keys["key"]).encrypt(nonce, frames, header)
    pn_off = len(head)
    sample = ct[4 - pn_len:4 - pn_len + 16]
    mask = _hp_mask(keys["hp"], sample)
    out = bytearray(header + ct)
    out[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        out[pn_off + i] ^= mask[1 + i]
    return bytes(out)


DCID, SCID = os.urandom(8), os.urandom(8)


def test_single_initial_client_hello():
    ch = client_hello(sni("quic.example"), alpn("h3"), groups(0x001D), versions(0x0304), ext(57, b"\x01\x02\x00\x00"))
    q = QuicAnalyzer()
    res = q.datagram(protect(crypto(0, ch), DCID, SCID), 1.0)
    r = res[0]
    assert r["event"] == "client_hello" and r["status"] == CONFIRMED and r["version"].startswith("QUIC v1")
    assert r["sni"]["real_sni"] == "quic.example" and r["application"] == "HTTP/3" and r["client_hello"]["quic_tp"]
    assert r["dcid"] == DCID.hex() and r["scid"] == SCID.hex()


def test_client_hello_split_over_two_initials_with_shuffled_frames():
    """Chrome 처럼 PQC 키 공유로 ClientHello 가 커서 Initial 두 개에 나뉘고, 프레임 순서도 섞인 경우."""
    ch = chrome_hello("split-quic.example", ech=True, alpns=("h3",))
    assert len(ch) > 1300
    a, b, c = ch[:500], ch[500:1000], ch[1000:]
    q = QuicAnalyzer()
    p1 = protect(crypto(500, b) + crypto(0, a), DCID, SCID, pn=0, pad_to=1250)
    p2 = protect(crypto(1000, c), DCID, SCID, pn=1, pad_to=1250)
    assert q.datagram(p1, 1.0) == []                                       # 아직 완성되지 않음
    r = q.datagram(p2, 1.01)[0]
    assert r["client_hello"]["sni"] == "split-quic.example" and r["client_hello"]["hybrid"] and r["initial_packets"] == 2
    assert r["sni"]["status"] == "estimated"                               # ECH 확장(GREASE 가능) → 확정하지 않음


def test_server_initial_server_hello_and_v2():
    for version in (V1, V2):
        q = QuicAnalyzer()
        ch = client_hello(sni("v.example"), alpn("h3"), versions(0x0304))
        q.datagram(protect(crypto(0, ch), DCID, SCID, version=version), 1.0)
        srv = protect(b"\x02\x00\x00\x00\x00" + crypto(0, server_hello(group=0x11EC, key_bytes=1120)), SCID, os.urandom(8),
                      version=version, server=True, key_dcid=DCID)
        r = q.datagram(srv, 1.02)[0]
        assert r["event"] == "server_hello" and r["server_hello"]["group"] == "X25519MLKEM768" and r["server_hello"]["hybrid"]


def test_doq_alpn():
    ch = client_hello(sni("dns.adguard-dns.com"), alpn("doq"), versions(0x0304))
    r = QuicAnalyzer().datagram(protect(crypto(0, ch), DCID, SCID), 1.0)[0]
    assert r["application"] == "DNS over QUIC (DoQ)"


def test_failure_reasons():
    q = QuicAnalyzer()
    gq = bytes([0xC0]) + b"Q050" + b"\x08" + DCID + b"\x00" + b"\x00" * 1200
    assert q.datagram(gq, 1.0)[0]["event"] == "unsupported_version" and "Google QUIC" in version_name(0x51303530)
    pkt = bytearray(protect(crypto(0, client_hello(sni("x.example"))), DCID, SCID))
    pkt[-5] ^= 0xFF                                                         # 손상
    r = q.datagram(bytes(pkt), 1.0)[0]
    assert r["event"] == "decrypt_failed" and r["status"] == FAILED
    vn = bytes([0x80]) + b"\x00\x00\x00\x00" + b"\x08" + DCID + b"\x08" + SCID + b"\x00\x00\x00\x01"
    assert q.datagram(vn, 1.0)[0]["status"] == LIMITED
    assert QuicAnalyzer().datagram(bytes([0x40]) + os.urandom(40), 1.0) == []   # 1-RTT short header: 읽을 수 없음


def test_lost_initial_reports_incomplete():
    ch = chrome_hello("lost.example", alpns=("h3",))
    q = QuicAnalyzer()
    q.datagram(protect(crypto(0, ch[:600]), DCID, SCID, pn=0), 1.0)       # 두 번째 Initial 이 손실됨
    fails = q.pending_incomplete(10.0)
    assert fails and fails[0]["event"] == "crypto_incomplete" and q.stats["crypto_incomplete"] == 1


def test_crypto_frame_parser_handles_ack_and_padding():
    frames = b"\x00\x00" + b"\x02\x05\x00\x00\x05" + crypto(0, b"abc") + b"\x01" + crypto(3, b"def")
    assert crypto_frames(frames) == [(0, b"abc"), (3, b"def")]


def test_client_initial_after_server_chose_new_cid():
    """서버 Initial 이후 클라이언트는 서버가 정한 CID 를 DCID 로 쓰지만, Initial 키는 원래 DCID 로 만든다."""
    q = QuicAnalyzer()
    ch = chrome_hello("newcid.example", ech=False, alpns=("h3",))
    flow = ("10.0.0.2", 55000, "203.0.113.9", 443)
    q.datagram(protect(crypto(0, ch[:700]), DCID, SCID, pn=0, pad_to=1250), 1.0, flow=flow)
    server_cid = os.urandom(8)
    q.datagram(protect(b"\x02\x00\x00\x00\x00", SCID, server_cid, version=V1, server=True, key_dcid=DCID), 1.01,
               flow=(flow[2], flow[3], flow[0], flow[1]))
    r = q.datagram(protect(crypto(700, ch[700:]), server_cid, SCID, pn=1, pad_to=1250, key_dcid=DCID), 1.02, flow=flow)
    assert r and r[0]["client_hello"]["sni"] == "newcid.example" and q.stats["decrypt_failed"] == 0


def test_zero_length_cids_use_address_pair():
    q = QuicAnalyzer()
    flow = ("10.0.0.2", 55001, "203.0.113.9", 443)
    q.datagram(protect(crypto(0, client_hello(sni("z.example"), alpn("h3"), versions(0x0304))), DCID, b""), 1.0, flow=flow)
    srv = protect(b"\x02\x00\x00\x00\x00" + crypto(0, server_hello(group=0x001D, key_bytes=32)), b"", os.urandom(8), server=True, key_dcid=DCID)
    r = q.datagram(srv, 1.01, flow=(flow[2], flow[3], flow[0], flow[1]))
    assert r and r[0]["event"] == "server_hello" and r[0]["server_hello"]["group"] == "x25519"


def test_server_initial_without_seen_client_initial_is_limited_not_failed():
    """캡처 시작 전에 시작된 연결: 서버 Initial 만 보이면 복호화 실패가 아니라 '분석 제한'."""
    q = QuicAnalyzer()
    srv = protect(b"\x02\x00\x00\x00\x00" + crypto(0, server_hello(group=0x001D, key_bytes=32)), os.urandom(8), os.urandom(8),
                  server=True, key_dcid=os.urandom(8))
    r = q.datagram(srv, 1.0, flow=("203.0.113.9", 443, "10.0.0.2", 55002))
    assert r[0]["event"] == "server_unmatched" and r[0]["status"] == LIMITED and q.stats["decrypt_failed"] == 0
