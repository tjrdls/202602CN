"""테스트용 TLS ClientHello/ServerHello 바이트 생성기 (실제 브라우저 형태를 흉내).

Chrome 계열: GREASE, TLS 1.3/1.2, ALPN h2·http/1.1, X25519MLKEM768(1216B)+x25519 Key Share,
GREASE ECH(또는 실제 ECH 공개 이름). Key Share 때문에 ClientHello 가 1,500바이트를 넘어 TCP 세그먼트가 나뉜다.
"""
import struct


def ext(t: int, body: bytes) -> bytes:
    return struct.pack("!HH", t, len(body)) + body


def sni(name: str) -> bytes:
    n = name.encode()
    e = b"\x00" + struct.pack("!H", len(n)) + n
    return ext(0, struct.pack("!H", len(e)) + e)


def alpn(*protos: str) -> bytes:
    body = b"".join(bytes([len(p)]) + p.encode() for p in protos)
    return ext(16, struct.pack("!H", len(body)) + body)


def groups(*gs: int) -> bytes:
    body = b"".join(struct.pack("!H", g) for g in gs)
    return ext(10, struct.pack("!H", len(body)) + body)


def versions(*vs: int) -> bytes:
    body = b"".join(struct.pack("!H", v) for v in vs)
    return ext(43, bytes([len(body)]) + body)


def key_share(*shares: tuple) -> bytes:
    body = b"".join(struct.pack("!HH", g, n) + b"\x11" * n for g, n in shares)
    return ext(51, struct.pack("!H", len(body)) + body)


def ech_outer() -> bytes:
    return ext(0xFE0D, b"\x00" + b"\x00\x01\x00\x01" + b"\x2a" + struct.pack("!H", 32) + b"\x22" * 32 + struct.pack("!H", 144) + b"\x33" * 144)


def client_hello(*exts: bytes, suites=(0x2A2A, 0x1301, 0x1302, 0x1303)) -> bytes:
    """핸드셰이크 메시지(유형 1부터)."""
    body = b"\x03\x03" + b"\x01" * 32 + b"\x20" + b"\x02" * 32
    cs = b"".join(struct.pack("!H", c) for c in suites)
    body += struct.pack("!H", len(cs)) + cs + b"\x01\x00"
    e = b"".join(exts)
    body += struct.pack("!H", len(e)) + e
    return b"\x01" + len(body).to_bytes(3, "big") + body


def chrome_hello(name="www.example.com", ech=True, public_name=None, alpns=("h2", "http/1.1")) -> bytes:
    exts = [ext(0x0A0A, b""), sni(public_name or name), alpn(*alpns), groups(0x1A1A, 0x11EC, 0x001D, 0x0017, 0x0018),
            versions(0x3A3A, 0x0304, 0x0303), key_share((0x1A1A, 1), (0x11EC, 1216), (0x001D, 32))]
    if ech:
        exts.append(ech_outer())
    return client_hello(*exts)


def server_hello(version=0x0304, group=0x11EC, key_bytes=1120) -> bytes:
    body = b"\x03\x03" + b"\x05" * 32 + b"\x20" + b"\x02" * 32 + b"\x13\x01" + b"\x00"
    e = ext(43, struct.pack("!H", version)) + ext(51, struct.pack("!HH", group, key_bytes) + b"\x44" * key_bytes)
    body += struct.pack("!H", len(e)) + e
    return b"\x02" + len(body).to_bytes(3, "big") + body


def record(hs: bytes, max_len: int = 16384) -> bytes:
    """핸드셰이크 메시지를 TLS 레코드(들)로 감싼다."""
    out = b""
    for i in range(0, len(hs), max_len):
        part = hs[i:i + max_len]
        out += b"\x16\x03\x01" + struct.pack("!H", len(part)) + part
    return out
