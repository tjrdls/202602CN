"""QUIC Initial 패킷 분석 (RFC 9000·9001·9369).

QUIC 의 첫 패킷(Initial)은 암호화되어 있지만, 키는 '공개된 솔트 + 패킷에 적힌 Destination Connection ID' 로
누구나 계산할 수 있다 (규격상 기밀성이 아니라 무결성용). 그래서 관찰자도 Initial 안의 TLS ClientHello 를 읽을 수 있다.

할 수 있는 것: 버전·Connection ID, Initial 복호화, CRYPTO 프레임 재조립(여러 Initial 에 나뉘고 순서가 섞여도),
ClientHello 의 SNI·ALPN·지원 그룹·PQC, 서버 Initial 의 ServerHello(선택 그룹), HTTP/3·DoQ 판정.
할 수 없는 것: Handshake·1-RTT 패킷(실제 HTTP/3 요청·응답)은 협상된 비밀 키로 암호화되어 읽을 수 없다.
"""
from __future__ import annotations

import struct
from collections import OrderedDict

from netcare.encrypted import CONFIRMED, ESTIMATED, FAILED, LIMITED
from netcare.encrypted.tls_hello import parse_client_hello, parse_server_hello, sni_view

V1, V2, DRAFT29 = 0x00000001, 0x6B3343CF, 0xFF00001D
SALTS = {V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
         V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
         DRAFT29: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899")}
LABELS = {V1: ("quic key", "quic iv", "quic hp"), DRAFT29: ("quic key", "quic iv", "quic hp"),
          V2: ("quicv2 key", "quicv2 iv", "quicv2 hp")}
VERSION_NAMES = {V1: "QUIC v1 (RFC 9000)", V2: "QUIC v2 (RFC 9369)", DRAFT29: "QUIC draft-29", 0: "버전 협상"}
MAX_CONNS = 4096
SERVER_PORTS = {443, 853, 8443, 784}


def version_name(v: int) -> str:
    if v in VERSION_NAMES:
        return VERSION_NAMES[v]
    if (v & 0x0F0F0F0F) == 0x0A0A0A0A:
        return f"GREASE 버전 0x{v:08x}"
    raw = v.to_bytes(4, "big")
    if raw[:1] == b"Q" or raw[:1] == b"T":
        return f"Google QUIC {raw.decode('ascii', 'replace')}"
    return f"알 수 없는 버전 0x{v:08x}"


def _varint(b: bytes, p: int) -> tuple[int, int]:
    first = b[p]
    n = 1 << (first >> 6)
    v = first & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[p + i]
    return v, p + n


# ───────────── 키 도출 (HKDF, RFC 8446 7.1 의 HKDF-Expand-Label) ─────────────
def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    import hmac
    import hashlib
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand_label(secret: bytes, label: str, length: int) -> bytes:
    import hmac
    import hashlib
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def initial_keys(dcid: bytes, version: int = V1, server: bool = False) -> dict:
    """Initial 키: {'key', 'iv', 'hp'}. 지원하지 않는 버전이면 KeyError."""
    secret = _hkdf_extract(SALTS[version], dcid)
    side = _expand_label(secret, "server in" if server else "client in", 32)
    k, iv, hp = LABELS[version]
    return {"key": _expand_label(side, k, 16), "iv": _expand_label(side, iv, 12), "hp": _expand_label(side, hp, 16)}


def _hp_mask(hp: bytes, sample: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


def _is_initial(first: int, version: int) -> bool:
    ptype = (first >> 4) & 0x03
    return ptype == (1 if version == V2 else 0)


def parse_long_header(d: bytes) -> dict | None:
    """Long header 공통부. QUIC long header 가 아니면 None."""
    if len(d) < 7 or not (d[0] & 0x80):
        return None
    version = struct.unpack("!I", d[1:5])[0]
    p = 5
    dl = d[p]
    if dl > 20 or p + 1 + dl >= len(d):
        return None                                 # 잘렸거나 형식이 틀린 패킷
    dcid = d[p + 1:p + 1 + dl]
    p += 1 + dl
    sl = d[p]
    if sl > 20 or p + 1 + sl > len(d):
        return None
    scid = d[p + 1:p + 1 + sl]
    p += 1 + sl
    return {"version": version, "dcid": dcid, "scid": scid, "hdr_end": p, "fixed_bit": bool(d[0] & 0x40)}


def _packet_size(d: bytes, h: dict) -> int:
    """Initial 패킷 하나의 전체 길이 (복호화 없이)."""
    p = h["hdr_end"]
    tok_len, p = _varint(d, p)
    p += tok_len
    length, p = _varint(d, p)
    return min(len(d), p + length)


def decrypt_initial(d: bytes, keys: dict, version: int) -> tuple[bytes, int, int]:
    """Initial 패킷 하나를 복호화 → (평문 프레임, 패킷 번호, 이 패킷의 전체 길이)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    h = parse_long_header(d)
    p = h["hdr_end"]
    tok_len, p = _varint(d, p)
    p += tok_len
    length, p = _varint(d, p)
    pn_off = p
    total = pn_off + length
    if total > len(d) or length < 20:
        raise ValueError("Initial 길이가 데이터보다 김 (잘린 패킷)")
    sample = d[pn_off + 4:pn_off + 20]
    mask = _hp_mask(keys["hp"], sample)
    first = d[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(d[pn_off:pn_off + pn_len], mask[1:1 + pn_len]))
    pn = int.from_bytes(pn_bytes, "big")
    header = bytes([first]) + d[1:pn_off] + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(keys["iv"], pn.to_bytes(12, "big")))
    plain = AESGCM(keys["key"]).decrypt(nonce, d[pn_off + pn_len:total], header)
    return plain, pn, total


def crypto_frames(plain: bytes) -> list[tuple[int, bytes]]:
    """Initial 평문에서 CRYPTO 프레임 (offset, data) 목록. Initial 에 올 수 있는 프레임만 해석."""
    out, p = [], 0
    while p < len(plain):
        t = plain[p]
        if t == 0x00:                                   # PADDING
            p += 1
        elif t == 0x01:                                 # PING
            p += 1
        elif t in (0x02, 0x03):                         # ACK
            p += 1
            _, p = _varint(plain, p)                    # largest
            _, p = _varint(plain, p)                    # delay
            cnt, p = _varint(plain, p)
            _, p = _varint(plain, p)                    # first range
            for _ in range(cnt):
                _, p = _varint(plain, p)
                _, p = _varint(plain, p)
            if t == 0x03:
                for _ in range(3):
                    _, p = _varint(plain, p)
        elif t == 0x06:                                 # CRYPTO
            off, p = _varint(plain, p + 1)
            n, p = _varint(plain, p)
            out.append((off, plain[p:p + n]))
            p += n
        elif t in (0x1C, 0x1D):                         # CONNECTION_CLOSE
            break
        else:
            break                                       # Initial 에 없어야 할 프레임 → 중단
    return out


class _Conn:
    __slots__ = ("version", "odcid", "scid", "client", "server", "client_done", "server_done", "packets", "result", "short_seen",
                 "first_ts", "failed", "client_port")

    def __init__(self, version, odcid, scid, ts):
        self.version, self.odcid, self.scid = version, odcid, scid
        self.client: dict[int, bytes] = {}
        self.server: dict[int, bytes] = {}
        self.client_done = self.server_done = False
        self.packets = 0
        self.result: dict | None = None
        self.short_seen = 0
        self.first_ts = ts
        self.failed = None
        self.client_port = None


def _contig(parts: dict[int, bytes]) -> bytes:
    out, pos = bytearray(), 0
    for o in sorted(parts):
        if o > pos:
            break
        d = parts[o]
        if o + len(d) > pos:
            out += d[pos - o:]
            pos = o + len(d)
    return bytes(out)


class QuicAnalyzer:
    """UDP 데이터그램을 받아 QUIC 연결별로 Initial 을 분석한다."""

    def __init__(self):
        self.conns: OrderedDict[bytes, _Conn] = OrderedDict()    # 원래 DCID → 연결
        self.by_scid: dict[bytes, bytes] = {}                     # 클라이언트 SCID → 원래 DCID (서버 Initial 찾기용)
        self.by_server_cid: dict[bytes, bytes] = {}               # 서버가 정한 SCID → 원래 DCID (클라이언트의 이후 Initial 용)
        self.by_flow: dict[tuple, bytes] = {}                     # (주소·포트 쌍) → 원래 DCID (CID 가 비어 있거나 겹칠 때)
        self.stats = {"datagrams": 0, "initial": 0, "decrypted": 0, "decrypt_failed": 0, "unsupported": 0, "hello_ok": 0,
                      "server_hello_ok": 0, "short_header": 0, "version_negotiation": 0, "crypto_incomplete": 0, "server_unmatched": 0}

    def datagram(self, d: bytes, ts: float, flow: tuple | None = None) -> list[dict]:
        """QUIC 일 수 있는 UDP 페이로드 하나. 새로 나온 분석 결과 목록을 돌려준다."""
        out = []
        self.stats["datagrams"] += 1
        p = 0
        while p < len(d):
            pkt = d[p:]
            if not (pkt[0] & 0x80):
                self.stats["short_header"] += 1    # 1-RTT: 협상된 키로 암호화 → 읽을 수 없음
                break
            h = parse_long_header(pkt)
            if h is None:
                break
            v = h["version"]
            if v == 0:
                self.stats["version_negotiation"] += 1
                out.append({"event": "version_negotiation", "status": LIMITED, "note": "서버가 다른 QUIC 버전을 요구(버전 협상)"})
                break
            if v not in SALTS:
                self.stats["unsupported"] += 1
                out.append({"event": "unsupported_version", "status": FAILED, "version": version_name(v),
                            "note": f"지원하지 않는 QUIC 버전({version_name(v)})이라 Initial 을 풀 수 없어요."})
                break
            if not _is_initial(pkt[0], v):
                break                              # Handshake·0-RTT 등: 읽을 수 없음, 이후 패킷도 건너뜀
            self.stats["initial"] += 1
            try:
                res, size = self._initial(pkt, h, ts, flow)
            except Exception as e:
                self.stats["decrypt_failed"] += 1
                out.append({"event": "decrypt_failed", "status": FAILED, "version": version_name(v),
                            "dcid": h["dcid"].hex(), "note": f"Initial 복호화 실패 ({type(e).__name__}: {str(e)[:80]})"})
                break
            if res:
                out.append(res)
            p += size
        return out

    def _initial(self, pkt: bytes, h: dict, ts: float, flow: tuple | None = None) -> tuple[dict | None, int]:
        v, dcid, scid = h["version"], h["dcid"], h["scid"]
        fkey = (min(flow[:2], flow[2:]), max(flow[:2], flow[2:])) if flow else None
        # 클라이언트의 두 번째 이후 Initial: DCID 가 서버가 정한 CID 로 바뀌어도 키는 '원래 DCID' 로 만든다
        odc = self.by_server_cid.get(dcid)
        if odc is not None and odc in self.conns and dcid not in self.conns:
            return self._client_initial(pkt, self.conns[odc], v, ts)
        # 서버 Initial: DCID 가 클라이언트의 SCID → 원래 DCID 로 키를 만든다 (CID 가 비어 있으면 주소·포트 쌍으로 찾음)
        odcid = self.by_scid.get(dcid) if dcid else None
        if (odcid is None or odcid not in self.conns) and fkey is not None and flow and self.by_flow.get(fkey) in self.conns \
                and self.conns[self.by_flow[fkey]].client_port != flow[1]:
            odcid = self.by_flow[fkey]
        from_server = bool(flow) and flow[1] in SERVER_PORTS and flow[3] not in SERVER_PORTS
        if from_server and (odcid is None or odcid not in self.conns):
            # 서버가 보낸 Initial 인데 이 연결의 첫 클라이언트 Initial 을 보지 못함 → 키를 만들 '원래 DCID' 를 모름.
            # 클라이언트 키로 풀려고 하면 반드시 실패하므로 시도하지 않고 '분석 제한'으로 표시한다.
            self.stats["server_unmatched"] += 1
            return {"event": "server_unmatched", "status": LIMITED, "version": version_name(v), "dcid": dcid.hex(),
                    "note": "서버의 Initial 이지만 같은 연결의 첫 클라이언트 Initial 을 보지 못해 키를 만들 수 없어요 (캡처 시작 전 연결·패킷 누락)."}, _packet_size(pkt, h)
        if odcid is not None and odcid in self.conns and dcid not in self.conns:
            conn = self.conns[odcid]
            plain, pn, size = decrypt_initial(pkt, initial_keys(odcid, v, server=True), v)
            self.stats["decrypted"] += 1
            if scid:
                self.by_server_cid[scid] = odcid
            for off, data in crypto_frames(plain):
                conn.server.setdefault(off, data)
            if not conn.server_done:
                buf = _contig(conn.server)
                if len(buf) >= 4 and len(buf) >= 4 + int.from_bytes(buf[1:4], "big"):
                    conn.server_done = True
                    sh = parse_server_hello(buf[:4 + int.from_bytes(buf[1:4], "big")])
                    self.stats["server_hello_ok"] += 0 if sh.get("error") else 1
                    return {"event": "server_hello", "status": CONFIRMED, "odcid": odcid.hex(), "server_hello": sh,
                            "version": version_name(v)}, size
            return None, size
        conn = self.conns.get(dcid)
        if conn is None:
            if len(self.conns) >= MAX_CONNS:
                old, c = self.conns.popitem(last=False)
                self.by_scid.pop(c.scid, None)
            conn = self.conns[dcid] = _Conn(v, dcid, scid, ts)
            conn.client_port = flow[1] if flow else None
            if scid:
                self.by_scid[scid] = dcid
            if fkey is not None:
                self.by_flow[fkey] = dcid
                if len(self.by_flow) > MAX_CONNS * 2:
                    self.by_flow.pop(next(iter(self.by_flow)))
        return self._client_initial(pkt, conn, v, ts)

    def _client_initial(self, pkt: bytes, conn, v: int, ts: float) -> tuple[dict | None, int]:
        dcid, scid = conn.odcid, conn.scid
        plain, pn, size = decrypt_initial(pkt, initial_keys(dcid, v), v)
        self.stats["decrypted"] += 1
        conn.packets += 1
        for off, data in crypto_frames(plain):
            conn.client.setdefault(off, data)
        if conn.client_done:
            return None, size
        buf = _contig(conn.client)
        if len(buf) < 4 or len(buf) < 4 + int.from_bytes(buf[1:4], "big"):
            return None, size                      # 다음 Initial 을 기다림 (ClientHello 가 여러 패킷에 나뉨)
        conn.client_done = True
        ch = parse_client_hello(buf[:4 + int.from_bytes(buf[1:4], "big")])
        self.stats["hello_ok"] += 0 if ch.get("error") else 1
        alpn = ch.get("alpn") or []
        app = ("HTTP/3" if any(a == "h3" or a.startswith("h3-") for a in alpn) else
               "DNS over QUIC (DoQ)" if "doq" in alpn else ("알 수 없음" if alpn else "ALPN 없음"))
        res = {"event": "client_hello", "status": CONFIRMED, "version": version_name(v), "dcid": dcid.hex(), "scid": scid.hex(),
               "initial_packets": conn.packets, "client_hello": ch, "sni": sni_view(ch), "application": app,
               "app_status": CONFIRMED if app != "알 수 없음" else ESTIMATED,
               "note": "ClientHello 의 ALPN 은 클라이언트가 '제안'한 목록이에요. 서버가 고른 값은 암호화된 영역에 있어 볼 수 없어요."}
        conn.result = res
        return res, size

    def pending_incomplete(self, now: float, timeout: float = 5.0) -> list[dict]:
        """CRYPTO 데이터가 끝까지 모이지 않은 연결 → 분석 실패(패킷 손실 등)."""
        out = []
        for k in [k for k, c in self.conns.items() if not c.client_done and c.failed is None and now - c.first_ts > timeout and c.client]:
            c = self.conns[k]
            c.failed = "crypto_incomplete"
            self.stats["crypto_incomplete"] += 1
            out.append({"event": "crypto_incomplete", "status": FAILED, "dcid": k.hex(), "version": version_name(c.version),
                        "note": "ClientHello 의 일부가 담긴 Initial 패킷이 오지 않았어요 (패킷 손실 또는 캡처 누락)."})
        return out
