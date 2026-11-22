"""TLS ClientHello / ServerHello 해석 (TCP·QUIC 공용).

입력은 '핸드셰이크 메시지' 바이트(유형 1바이트부터)다. TCP 에서는 TLS 레코드를 벗긴 뒤,
QUIC 에서는 CRYPTO 프레임을 이어 붙인 뒤 이 함수에 넣는다.

읽는 것: 실제 협상 버전(supported_versions), SNI, ALPN, 지원 그룹, Key Share 그룹, ECH·ESNI 확장,
PQC 하이브리드 키 교환 그룹. GREASE(무작위 예약값)는 제외한다.
읽지 않는 것: 암호화된 확장(ECH 안쪽 ClientHello 등). 볼 수 없는 값은 None 으로 둔다.
"""
from __future__ import annotations

import struct
from typing import Any

EXT_SNI, EXT_GROUPS, EXT_ALPN, EXT_VERSIONS, EXT_KEY_SHARE, EXT_ECH, EXT_ESNI, EXT_QUIC_TP = 0, 10, 16, 43, 51, 0xFE0D, 0xFFCE, 57
EXT_QUIC_TP_DRAFT = 0xFFA5
# ECH 바깥(공개) 이름: 이 이름이 SNI 로 보이고 ECH 확장이 있으면 실제 ECH 사용이 확실하다.
# 정적 목록(공개적으로 알려진 서비스) + 관찰한 DNS HTTPS 레코드의 ECHConfig 에서 배운 이름(learn_public_name)
ECH_PUBLIC_NAMES = {"cloudflare-ech.com", "public.tls-ech.dev"}
LEARNED_PUBLIC_NAMES: dict[str, str] = {}      # 공개 이름 → 이 이름을 알려 준 도메인 (DNS HTTPS 레코드)


def learn_public_name(public_name: str, for_domain: str):
    if public_name and len(LEARNED_PUBLIC_NAMES) < 5000:
        LEARNED_PUBLIC_NAMES[public_name.lower().rstrip(".")] = for_domain


def parse_ech_config_list(b: bytes) -> list[str]:
    """ECHConfigList(DNS HTTPS 레코드의 ech 값)에서 public_name 들을 읽는다."""
    names, p = [], 2
    try:
        end = 2 + _u16(b, 0)
        while p + 4 <= min(end, len(b)):
            ver, ln = _u16(b, p), _u16(b, p + 2)
            c = b[p + 4:p + 4 + ln]
            p += 4 + ln
            if ver != 0xFE0D:
                continue
            q = 1 + 2                                   # config_id, kem_id
            q += 2 + _u16(c, q)                         # public_key
            q += 2 + _u16(c, q)                         # cipher_suites
            q += 1                                      # maximum_name_length
            n = c[q]
            names.append(c[q + 1:q + 1 + n].decode("ascii", "replace"))
    except (IndexError, struct.error):
        pass
    return names

VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00", 0x639A: "SecP256r1Kyber768Draft00",
}
PQC_GROUPS = {0x0200, 0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED, 0x6399, 0x639A}
HYBRID_GROUPS = {0x11EB, 0x11EC, 0x11ED, 0x6399, 0x639A}


def is_grease(v: int) -> bool:
    """GREASE 값(0x0A0A, 0x1A1A …): 서버 호환성 시험용 무의미한 값이라 분석에서 뺀다."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def group_name(g: int) -> str:
    return GROUPS.get(g, f"0x{g:04x}")


def _u16(b: bytes, p: int) -> int:
    return struct.unpack("!H", b[p:p + 2])[0]


def _exts(b: bytes, p: int):
    """확장 목록 (유형, 내용) 을 차례로 돌려준다."""
    total = _u16(b, p)
    p += 2
    end = min(len(b), p + total)
    while p + 4 <= end:
        t, n = struct.unpack("!HH", b[p:p + 4])
        p += 4
        yield t, b[p:p + n]
        p += n


def parse_client_hello(hs: bytes) -> dict:
    """ClientHello 를 해석한다. 실패해도 예외 없이 읽은 데까지와 오류를 돌려준다."""
    out: dict[str, Any] = {"type": "client_hello", "complete": False, "error": None, "legacy_version": None,
                           "versions": [], "tls_version": None, "sni": None, "alpn": [], "groups": [], "key_share": [],
                           "pqc": [], "hybrid": False, "ech": False, "ech_type": None, "esni": False, "cipher_suites": 0,
                           "quic_tp": False}
    try:
        if not hs or hs[0] != 1:
            out["error"] = "ClientHello 가 아님"
            return out
        mlen = int.from_bytes(hs[1:4], "big")
        if len(hs) < 4 + mlen:
            out["error"] = f"ClientHello 가 잘림 ({len(hs) - 4}/{mlen} 바이트)"
        body = hs[4:4 + mlen]
        out["legacy_version"] = VERSIONS.get(_u16(body, 0), f"0x{_u16(body, 0):04x}")
        p = 2 + 32
        p += 1 + body[p]                                    # session id
        cs = _u16(body, p)
        out["cipher_suites"] = len([1 for i in range(0, cs, 2) if not is_grease(_u16(body, p + 2 + i))])
        p += 2 + cs
        p += 1 + body[p]                                    # compression
        if p + 2 > len(body):
            out["tls_version"] = out["legacy_version"]
            out["complete"] = out["error"] is None
            return out
        for t, d in _exts(body, p):
            if is_grease(t):
                continue
            if t == EXT_SNI and len(d) >= 5 and d[2] == 0:
                n = _u16(d, 3)
                out["sni"] = d[5:5 + n].decode("ascii", "replace") or None
            elif t == EXT_ALPN and len(d) >= 2:
                q, end = 2, 2 + _u16(d, 0)
                while q < min(end, len(d)):
                    n = d[q]
                    out["alpn"].append(d[q + 1:q + 1 + n].decode("ascii", "replace"))
                    q += 1 + n
            elif t == EXT_GROUPS and len(d) >= 2:
                out["groups"] = [group_name(g) for i in range(2, 2 + _u16(d, 0), 2) if i + 2 <= len(d)
                                 for g in [_u16(d, i)] if not is_grease(g)]
                out["pqc"] = [group_name(_u16(d, i)) for i in range(2, 2 + _u16(d, 0), 2) if i + 2 <= len(d) and _u16(d, i) in PQC_GROUPS]
            elif t == EXT_VERSIONS and len(d) >= 1:
                vs = [_u16(d, 1 + i) for i in range(0, d[0], 2) if 1 + i + 2 <= len(d)]
                out["versions"] = [VERSIONS.get(v, f"0x{v:04x}") for v in vs if not is_grease(v)]
            elif t == EXT_KEY_SHARE and len(d) >= 2:
                q, end = 2, 2 + _u16(d, 0)
                while q + 4 <= min(end, len(d)):
                    g, n = _u16(d, q), _u16(d, q + 2)
                    if not is_grease(g):
                        out["key_share"].append({"group": group_name(g), "bytes": n, "pqc": g in PQC_GROUPS})
                        if g in HYBRID_GROUPS:
                            out["hybrid"] = True
                    q += 4 + n
            elif t == EXT_ECH:
                out["ech"] = True
                out["ech_type"] = "outer" if d[:1] == b"\x00" else ("inner" if d[:1] == b"\x01" else None)
            elif t == EXT_ESNI:
                out["esni"] = True
            elif t in (EXT_QUIC_TP, EXT_QUIC_TP_DRAFT):
                out["quic_tp"] = True
        vs = [v for v in out["versions"] if v.startswith("TLS")]
        out["tls_version"] = max(vs) if vs else out["legacy_version"]
        out["complete"] = out["error"] is None
    except (IndexError, struct.error) as e:
        out["error"] = out["error"] or f"형식 오류 ({type(e).__name__})"
    return out


def parse_server_hello(hs: bytes) -> dict:
    """ServerHello: 서버가 실제로 고른 버전·키 교환 그룹·ALPN(1.2)을 읽는다 (TLS 1.3 에서도 평문)."""
    out: dict[str, Any] = {"type": "server_hello", "error": None, "tls_version": None, "group": None, "hybrid": False,
                           "pqc": False, "hrr": False}
    try:
        if not hs or hs[0] != 2:
            out["error"] = "ServerHello 가 아님"
            return out
        body = hs[4:4 + int.from_bytes(hs[1:4], "big")]
        legacy = _u16(body, 0)
        rnd = body[2:34]
        # HelloRetryRequest 는 ServerHello 와 같은 형식에 고정 난수를 쓴다 (RFC 8446 4.1.3)
        out["hrr"] = rnd.hex() == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
        p = 34
        p += 1 + body[p]
        p += 2 + 1                                          # cipher suite, compression
        out["tls_version"] = VERSIONS.get(legacy, f"0x{legacy:04x}")
        if p + 2 <= len(body):
            for t, d in _exts(body, p):
                if t == EXT_VERSIONS and len(d) >= 2:
                    out["tls_version"] = VERSIONS.get(_u16(d, 0), f"0x{_u16(d, 0):04x}")
                elif t == EXT_KEY_SHARE and len(d) >= 2:
                    g = _u16(d, 0)
                    out["group"] = group_name(g)
                    out["pqc"] = g in PQC_GROUPS
                    out["hybrid"] = g in HYBRID_GROUPS
    except (IndexError, struct.error) as e:
        out["error"] = f"형식 오류 ({type(e).__name__})"
    return out


def sni_view(ch: dict) -> dict:
    """SNI 를 세 가지로 나눈다. 볼 수 없거나 확정할 수 없는 값은 추측하지 않고 None + 상태로 둔다.

    observed_sni : 패킷에 평문으로 실려 있던 이름 (있으면 언제나 '확인됨' — 보낸 것은 사실)
    real_sni     : 실제 접속 도메인이라고 확정할 수 있을 때만 (ECH 확장이 없을 때)
    outer_sni    : ECH 사용이 확실할 때의 바깥(공개) 이름
    """
    from netcare.encrypted import CONFIRMED, ESTIMATED, FAILED, LIMITED
    sni = ch.get("sni")
    base = {"observed_sni": sni, "real_sni": None, "outer_sni": None}
    if ch.get("ech"):
        low = (sni or "").lower()
        if low in ECH_PUBLIC_NAMES or low in LEARNED_PUBLIC_NAMES:
            src = (f" (이 이름은 DNS HTTPS 레코드에서 {LEARNED_PUBLIC_NAMES[low]} 의 ECH 공개 이름으로 확인했어요)" if low in LEARNED_PUBLIC_NAMES else "")
            return {**base, "outer_sni": sni, "status": LIMITED, "ech": "confirmed",
                    "note": "ECH 사용이 확실해요. 보이는 이름은 바깥(공개) 이름이고 실제 접속 도메인은 암호화되어 볼 수 없어요." + src}
        return {**base, "status": ESTIMATED, "ech": "unconfirmed",
                "note": "ECH 확장이 있어요. 브라우저는 ECH를 쓰지 않을 때도 가짜(GREASE) ECH를 붙이므로, 보이는 이름이 실제 도메인인지 "
                        "ECH 바깥(공개) 이름인지 패킷만으로는 확정할 수 없어요."}
    if ch.get("esni"):
        return {**base, "outer_sni": sni, "status": LIMITED, "ech": "esni", "note": "ESNI(구형 방식)로 실제 도메인이 암호화되어 있어요."}
    if sni:
        return {**base, "real_sni": sni, "status": CONFIRMED, "ech": "none", "note": "ClientHello에서 평문 SNI를 읽었어요 (ECH 확장 없음)."}
    return {**base, "status": FAILED if ch.get("error") else LIMITED, "ech": "none",
            "note": ch.get("error") or "ClientHello에 SNI가 없어요 (IP 주소로 직접 접속 등)."}
