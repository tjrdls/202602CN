"""패킷 파서.

Scapy 패킷을 다음 두 가지 형태로 바꾼다.
1) parse_packet(): 목록/통계/탐지에 쓰는 가벼운 요약 레코드(dict)
2) dissect(): 상세 화면용 계층 트리 + 헥사 덤프 (원본 바이트를 다시 해석)

주의: HTTPS(TLS) 본문은 암호화되어 있으므로 해석하지 않는다.
TLS 레코드 헤더와 ClientHello 의 SNI(평문으로 전송되는 접속 도메인)만 읽는다.
"""
from __future__ import annotations

import struct
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether, Loopback
from scapy.packet import Packet, Padding, Raw

from netcare.analysis import terms

try:  # 선택적 계층
    from scapy.layers.l2 import CookedLinux  # type: ignore
except ImportError:  # pragma: no cover
    CookedLinux = None

FIRST_LAYERS: dict[str, type] = {"Ether": Ether, "Loopback": Loopback, "IP": IP, "IPv6": IPv6}
if CookedLinux is not None:
    FIRST_LAYERS["CookedLinux"] = CookedLinux

ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "VLAN", 0x88CC: "LLDP"}

TLS_CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data(암호화됨)"}
TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2(또는 1.3 호환 표기)", 0x0304: "TLS 1.3"}


def flags_str(tcp) -> str:
    """Scapy TCP 플래그를 'SA', 'PA' 같은 문자열로 (순서: F S R P A U E C)."""
    v = int(tcp.flags)
    out = ""
    for bit, ch in ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")):
        if v & bit:
            out += ch
    return out


def _canon_flags(f: str) -> str:
    """친화 설명 조회용: 주요 플래그(S, A, F, R, P)만 정해진 순서로."""
    core = "".join(ch for ch in "SFRPA" if ch in f)
    # 사전 키 형식에 맞춤: SA, PA, FA, RA
    if core == "SA" or core == "S":
        return core
    if "R" in core:
        return "RA" if "A" in core else "R"
    if "F" in core:
        return "FA" if "A" in core else "F"
    if "P" in core:
        return "PA"
    return core


def parse_tls(payload: bytes) -> dict | None:
    """TLS 레코드 헤더와 ClientHello SNI 를 읽는다. TLS 가 아니면 None."""
    if len(payload) < 5:
        return None
    ctype, ver, length = payload[0], struct.unpack("!H", payload[1:3])[0], struct.unpack("!H", payload[3:5])[0]
    if ctype not in TLS_CONTENT_TYPES or ver not in TLS_VERSIONS:
        return None
    info: dict[str, Any] = {"content_type": TLS_CONTENT_TYPES[ctype], "version": TLS_VERSIONS[ver], "length": length}
    if ctype == 22 and len(payload) > 9 and payload[5] == 1:  # Handshake / ClientHello
        info["handshake"] = "ClientHello(접속 시작 인사)"
        sni = _extract_sni(payload[5:])
        if sni:
            info["sni"] = sni
    elif ctype == 22 and len(payload) > 5 and payload[5] == 2:
        info["handshake"] = "ServerHello(서버 응답 인사)"
    return info


def _extract_sni(hs: bytes) -> str | None:
    try:
        p = 4 + 2 + 32  # handshake header, version, random
        sid_len = hs[p]; p += 1 + sid_len
        cs_len = struct.unpack("!H", hs[p:p + 2])[0]; p += 2 + cs_len
        cm_len = hs[p]; p += 1 + cm_len
        ext_total = struct.unpack("!H", hs[p:p + 2])[0]; p += 2
        end = min(len(hs), p + ext_total)
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", hs[p:p + 4]); p += 4
            if etype == 0 and elen >= 5:  # server_name
                name_len = struct.unpack("!H", hs[p + 3:p + 5])[0]
                name = hs[p + 5:p + 5 + name_len].decode("ascii", "replace")
                return name or None
            p += elen
    except (IndexError, struct.error):
        return None
    return None


def parse_packet(pkt: Packet, local_ips: set[str] | None = None, local_macs: set[str] | None = None,
                 source: str = "live", snaplen: int = 2048, store_raw: bool = True) -> dict:
    """Scapy 패킷 → 요약 레코드. 어떤 패킷이 와도 예외를 던지지 않도록 방어적으로 작성."""
    local_ips = local_ips or set()
    local_macs = local_macs or set()
    if getattr(pkt, "raw_packet_cache", None) is None and not isinstance(pkt, Raw):
        # 직접 만든 패킷(테스트 데이터)은 길이·체크섬 같은 자동 필드가 비어 있으므로 한 번 빌드한다
        t = getattr(pkt, "time", None)
        try:
            pkt = pkt.__class__(bytes(pkt))
            if t is not None:
                pkt.time = t
        except Exception:
            pass
    rec: dict[str, Any] = {
        "ts": float(getattr(pkt, "time", 0) or 0),
        "length": len(pkt),
        "source": source,
        "first_layer": pkt.__class__.__name__,
        "src_mac": None, "dst_mac": None, "ethertype": None,
        "ip_version": None, "src": None, "dst": None, "ttl": None, "ip_len": None,
        "proto": "OTHER", "sport": None, "dport": None,
        "flags": None, "seq": None, "ack": None, "window": None, "udp_len": None, "payload_len": 0,
        "arp_op": None, "arp_hwsrc": None,
        "icmp_type": None, "icmp_code": None,
        "dns_qname": None, "dns_qtype": None, "dns_qr": None, "dns_rcode": None, "dns_id": None, "dns_answers": None,
        "tls": None, "service": "", "service_desc": "", "service_port": None,
        "direction": "other",
    }
    try:
        if pkt.haslayer(Ether):
            e = pkt[Ether]
            rec["src_mac"], rec["dst_mac"] = e.src, e.dst
            rec["ethertype"] = f"0x{int(e.type):04x} ({ETHERTYPES.get(int(e.type), '기타')})"
        if pkt.haslayer(IP):
            ip = pkt[IP]
            rec.update(ip_version=4, src=ip.src, dst=ip.dst, ttl=int(ip.ttl), ip_len=int(ip.len or 0))
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            rec.update(ip_version=6, src=ip6.src, dst=ip6.dst, ttl=int(ip6.hlim), ip_len=int(ip6.plen or 0) + 40)
        elif pkt.haslayer(ARP):
            a = pkt[ARP]
            rec.update(proto="ARP", src=a.psrc, dst=a.pdst, arp_op=int(a.op), arp_hwsrc=str(a.hwsrc).lower())

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            rec.update(proto="TCP", sport=int(t.sport), dport=int(t.dport), flags=flags_str(t),
                       seq=int(t.seq), ack=int(t.ack), window=int(t.window))
            payload = bytes(t.payload) if t.payload else b""
            # 이더넷 최소 길이를 맞추는 채움 바이트(Padding)는 데이터가 아님
            ip_total = rec["ip_len"] or 0
            if ip_total and rec["ip_version"] == 4:
                ihl = int(pkt[IP].ihl or 5) * 4
                rec["payload_len"] = max(0, ip_total - ihl - int(t.dataofs or 5) * 4)
            else:
                rec["payload_len"] = len(payload) - (len(t[Padding]) if t.haslayer(Padding) else 0)
            if payload:
                rec["tls"] = parse_tls(payload)  # TLS 형식이 아니면 None
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            rec.update(proto="UDP", sport=int(u.sport), dport=int(u.dport), udp_len=int(u.len or 0))
        elif pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            rec.update(proto="ICMP", icmp_type=int(ic.type), icmp_code=int(ic.code))
        elif rec["ip_version"] == 6 and int(pkt[IPv6].nh) == 58:
            rec["proto"] = "ICMPv6"
            try:
                rec["icmp_type"] = int(bytes(pkt[IPv6].payload)[0])
            except (IndexError, TypeError):
                pass
        elif rec["ip_version"] == 4 and int(pkt[IP].proto) == 2:
            rec["proto"] = "IGMP"

        if pkt.haslayer(DNS):
            d = pkt[DNS]
            rec["dns_id"] = int(d.id)
            rec["dns_qr"] = int(d.qr)
            rec["dns_rcode"] = int(d.rcode)
            try:
                if d.qd:
                    q = d.qd[0] if hasattr(d.qd, "__getitem__") else d.qd
                    rec["dns_qname"] = q.qname.decode("utf-8", "replace").rstrip(".")
                    rec["dns_qtype"] = int(q.qtype)
            except (AttributeError, IndexError):
                pass
            if d.qr == 1 and d.an:
                answers = []
                try:
                    for rr in d.an:
                        if getattr(rr, "type", None) in (1, 28):  # A, AAAA
                            answers.append(str(rr.rdata))
                except (AttributeError, TypeError):
                    pass
                rec["dns_answers"] = answers[:20] or None

        name, desc, sp = terms.service_for(rec["proto"], rec["sport"], rec["dport"])
        rec.update(service=name, service_desc=desc, service_port=sp)
        if rec["proto"] == "ICMP":
            rec.update(service="ICMP", service_desc=terms.PROTOCOLS["ICMP"])
        elif rec["proto"] in ("ARP", "IGMP", "ICMPv6"):
            rec.update(service=rec["proto"], service_desc=terms.PROTOCOLS[rec["proto"]])

        # 방향: MAC 이 가장 정확하고, 없으면(루프백 등) IP 로 판정
        src_local = rec["src_mac"] in local_macs or rec["src"] in local_ips
        dst_local = rec["dst_mac"] in local_macs or rec["dst"] in local_ips
        if src_local and dst_local:
            rec["direction"] = "local"
        elif src_local:
            rec["direction"] = "up"
        elif dst_local:
            rec["direction"] = "down"

        rec["info"] = technical_info(rec)
        rec["friendly"] = friendly_summary(rec, local_ips)
    except Exception as exc:  # 손상된/특이 패킷도 목록에서 사라지지 않게
        rec["info"] = f"해석 중 오류: {type(exc).__name__}"
        rec["friendly"] = "해석할 수 없는 형식의 데이터예요"
    if store_raw:
        try:
            rec["raw"] = bytes(pkt)[:snaplen]
        except Exception:
            rec["raw"] = None
    return rec


def technical_info(r: dict) -> str:
    p = r["proto"]
    if p == "TCP":
        s = f"{r['sport']} → {r['dport']} [{r['flags']}] Seq={r['seq']} Ack={r['ack']} Win={r['window']}"
        if r.get("tls"):
            t = r["tls"]
            s += f" · TLS {t.get('content_type')}"
            if t.get("sni"):
                s += f" SNI={t['sni']}"
        return s
    if p == "UDP":
        s = f"{r['sport']} → {r['dport']} Len={r['udp_len']}"
        if r.get("dns_qname"):
            kind = "응답" if r["dns_qr"] else "질의"
            s += f" · DNS {kind} {r['dns_qname']}"
            if r["dns_qr"]:
                s += f" rcode={r['dns_rcode']}"
        return s
    if p in ("ICMP", "ICMPv6"):
        return f"type={r['icmp_type']} code={r['icmp_code']}"
    if p == "ARP":
        return f"누가 {r['dst']} 인가요? / {r['src']}"
    return r.get("ethertype") or r.get("first_layer") or ""


def friendly_summary(r: dict, local_ips: set[str]) -> str:
    """초보자용 한 문장 설명."""
    p = r["proto"]
    svc = r.get("service_desc") or terms.PROTOCOLS.get(p, "통신")
    if p == "TCP":
        f = _canon_flags(r.get("flags") or "")
        action = terms.TCP_FLAG_FRIENDLY.get(f, "데이터 주고받기")
        if r.get("tls", {}) and r["tls"].get("sni"):
            return f"{r['tls']['sni']} 사이트에 암호화 연결을 시작해요 ({svc})"
        return f"{svc} · {action}"
    if p == "UDP":
        if r.get("dns_qname"):
            if r.get("dns_qr"):
                rc = r.get("dns_rcode") or 0
                if rc == 0:
                    return f"'{r['dns_qname']}' 주소를 알려 줬어요 (DNS 응답)"
                return f"'{r['dns_qname']}' 주소 조회 실패: {terms.DNS_RCODES.get(rc, rc)}"
            return f"'{r['dns_qname']}' 의 주소를 물어봐요 (DNS 질의)"
        return svc
    if p == "ICMP":
        return f"연결 상태 확인 · {terms.ICMP_TYPES.get(r.get('icmp_type'), '기타 메시지')}"
    if p == "ARP":
        return f"같은 네트워크에서 {r['dst']} 장치를 찾고 있어요"
    return terms.PROTOCOLS.get(p, "기타 통신")


# ───────────────────────────── 상세 분석 (계층 트리) ─────────────────────────────

def rebuild(raw: bytes, first_layer: str) -> Packet:
    cls = FIRST_LAYERS.get(first_layer)
    if cls is None:
        return Raw(raw)
    return cls(raw)


def _layer_display_name(layer: Packet) -> str:
    n = layer.__class__.__name__
    return "Ethernet" if n == "Ether" else n


def dissect(raw: bytes, first_layer: str) -> dict:
    """원본 바이트를 계층 트리로. 각 필드에 한국어 이름과 설명을 붙인다."""
    pkt = rebuild(raw, first_layer)
    layers = []
    cur = pkt
    offset = 0
    total = len(raw)
    while cur is not None and not isinstance(cur, type(None)):
        lname = _layer_display_name(cur)
        try:
            hdr_len = len(cur) - len(cur.payload) if cur.payload else len(cur)
        except Exception:
            hdr_len = 0
        fields = []
        if lname in ("Raw", "Padding"):
            data = bytes(cur.load) if hasattr(cur, "load") else bytes(cur)
            note = ""
            parent = layers[-1]["name"] if layers else ""
            if parent == "TCP":
                tls = parse_tls(data)
                if tls:
                    if tls.get("content_type", "").startswith("Application Data"):
                        note = "TLS로 암호화된 데이터예요. 복호화 키 없이는 내용을 볼 수 없어요 (NetCare 는 복호화하지 않아요)."
                    else:
                        note = ("TLS 연결 설정(핸드셰이크) 과정이에요. 접속 도메인(SNI) 같은 일부 정보는 평문이지만, "
                                "연결이 맺어진 뒤 주고받는 실제 내용은 암호화되어 볼 수 없어요.")
                    for k, v in tls.items():
                        fields.append({"name": f"tls.{k}", "label": {"content_type": "TLS 레코드 종류", "version": "레코드 계층 버전(호환용 표기)",
                                       "length": "레코드 길이", "handshake": "핸드셰이크", "sni": "접속 도메인(SNI, 평문)"}.get(k, k),
                                       "value": str(v), "desc": ""})
            fields.append({"name": "length", "label": "데이터 크기", "value": f"{len(data)} 바이트", "desc": ""})
            preview = data[:64]
            if not note:
                printable = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
                fields.append({"name": "preview", "label": "앞부분 미리보기(ASCII)", "value": printable, "desc": "글자로 표시할 수 없는 바이트는 '.'으로 보여요"})
            layers.append({"name": lname, "title": terms.LAYER_NAMES.get(lname, lname), "offset": offset,
                           "length": len(data), "fields": fields, "note": note})
            break
        for fdesc in cur.fields_desc:
            fname = fdesc.name
            try:
                val = cur.getfieldval(fname)
                shown = fdesc.i2repr(cur, val)
            except Exception:
                shown = "?"
            label, desc = terms.FIELD_LABELS.get((lname, fname), (fname, ""))
            if lname == "TCP" and fname == "flags":
                fl = flags_str(cur)
                shown = f"{fl} = " + ", ".join(terms.TCP_FLAG_NAMES[c] for c in fl if c in terms.TCP_FLAG_NAMES)
            if lname == "DNS" and fname in ("qd", "an", "ns", "ar"):
                shown = _summarize_dns_section(cur, fname)
            shown = str(shown)
            if len(shown) > 300:
                shown = shown[:300] + "…"
            fields.append({"name": fname, "label": label, "value": shown, "desc": desc})
        layers.append({"name": lname, "title": terms.LAYER_NAMES.get(lname, lname), "offset": offset,
                       "length": hdr_len, "fields": fields, "note": ""})
        offset += max(hdr_len, 0)
        nxt = cur.payload
        if nxt is None or len(nxt) == 0 or nxt.__class__.__name__ == "NoPayload":
            break
        cur = nxt
    return {"layers": layers, "hex": hexdump(raw), "total": total}


def _summarize_dns_section(d, fname: str) -> str:
    try:
        sec = getattr(d, fname)
        if not sec:
            return "(없음)"
        items = []
        for rr in sec:
            nm = getattr(rr, "qname", None) or getattr(rr, "rrname", b"")
            nm = nm.decode("utf-8", "replace") if isinstance(nm, bytes) else str(nm)
            rd = getattr(rr, "rdata", None)
            items.append(f"{nm} {rd}" if rd is not None else nm)
        return "; ".join(items)
    except Exception:
        return "?"


def hexdump(raw: bytes, width: int = 16) -> list[dict]:
    rows = []
    for i in range(0, len(raw), width):
        chunk = raw[i:i + width]
        rows.append({
            "offset": f"{i:04x}",
            "hex": " ".join(f"{b:02x}" for b in chunk),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
        })
    return rows
