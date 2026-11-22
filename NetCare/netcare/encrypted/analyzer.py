"""암호화 통신 분석기 — 캡처 엔진이 패킷마다 호출한다.

패킷 레코드(parse_packet 결과)와 L4 페이로드를 받아
- TCP: 재조립 → ClientHello/ServerHello 해석 (SNI·버전·ALPN·그룹·PQC·ECH)
- UDP: QUIC Initial 복호화 → ClientHello/ServerHello, HTTP/3·DoQ 판정
- DNS: 일반 DNS / DoT / DoQ / DoH(추정) 분류
결과를 레코드에 붙이고(rec['enc'], rec['tags']), 패킷 분석 화면용 통계를 모은다.

CPU·메모리: 핸드셰이크 구간만 다룬다(TLS 는 ClientHello·ServerHello 까지, QUIC 은 Initial 만).
그 뒤의 암호화 데이터는 바이트 수만 센다.
"""
from __future__ import annotations

from collections import Counter, OrderedDict, deque

from netcare.encrypted import CONFIRMED, ESTIMATED, FAILED, LIMITED, STATUS_KO
from netcare.encrypted.dns_class import DnsClassifier
from netcare.encrypted.quic import QuicAnalyzer
from netcare.encrypted.reassembly import TcpReassembler, looks_like_tls_handshake
from netcare.encrypted.tls_hello import sni_view

QUIC_PORTS = {443, 853, 8443, 784}
MAX_FLOWS = 50000


class EncryptedAnalyzer:
    def __init__(self):
        self.reasm = TcpReassembler()
        self.quic = QuicAnalyzer()
        self.dns = DnsClassifier()
        self.flow_kind: OrderedDict[tuple, str] = OrderedDict()     # 흐름 → tls / quic (암호화 흐름 표시)
        self.events: deque = deque(maxlen=300)                       # 최근 핸드셰이크 분석 결과 (화면 상세용)
        self.c = Counter()                                            # 각종 건수
        self.proto_bytes = Counter()                                  # TCP / UDP / QUIC / 기타
        self.tls_versions = Counter()
        self.alpn = Counter()
        self.ech = Counter()
        self.sni_status = Counter()
        self.bytes_total = 0
        self.bytes_opaque = 0                                         # 내용을 볼 수 없는(암호화된) 바이트

    # ───────────── 흐름 표시 ─────────────
    @staticmethod
    def _fkey(r):
        a, b = (r["src"], r.get("sport")), (r["dst"], r.get("dport"))
        return (r.get("proto"),) + (a + b if a <= b else b + a)

    def _mark(self, r, kind):
        k = self._fkey(r)
        self.flow_kind[k] = kind
        self.flow_kind.move_to_end(k)
        while len(self.flow_kind) > MAX_FLOWS:
            self.flow_kind.popitem(last=False)

    # ───────────── 패킷 처리 ─────────────
    def process(self, r: dict, payload: bytes | None) -> None:
        proto = r.get("proto")
        size = r.get("length") or 0
        self.bytes_total += size
        if r.get("ech_public_names"):
            from netcare.encrypted.tls_hello import learn_public_name
            for n in r["ech_public_names"]:
                learn_public_name(n, r.get("dns_qname") or "")
            self.c["ech_configs_seen"] += 1
        tags = set()
        tls_res = quic_res = None
        if proto == "TCP":
            tls_res = self._tcp(r, payload or b"", tags)
        elif proto == "UDP" and payload:
            quic_res = self._udp(r, payload, tags)
        kind = self.flow_kind.get(self._fkey(r)) if proto in ("TCP", "UDP") else None
        if kind == "quic":
            tags.add("quic")
            self.proto_bytes["QUIC"] += size
        else:
            self.proto_bytes[proto if proto in ("TCP", "UDP") else "기타"] += size
        if kind == "tls":
            tags.add("tls")
        # 내용을 볼 수 없는 패킷: TLS 응용 데이터, QUIC 핸드셰이크 이후(1-RTT 등)
        if (kind == "tls" and (r.get("tls") or {}).get("content_type", "").startswith("Application")) or \
                (kind == "quic" and payload and not (payload[0] & 0x80)):
            tags.add("opaque")
            self.bytes_opaque += size
        d = self.dns.packet(r, tls=(tls_res or {}).get("hello"), quic=quic_res)
        if d and d.get("kind") != "dns":
            tags.add(d["kind"] if d["status"] == CONFIRMED else d["kind"] + "_est")
        elif d:
            tags.add("dns")
        if tags:
            r["tags"] = sorted(set(r.get("tags") or []) | tags)

    def _tcp(self, r, payload, tags) -> dict | None:
        fl = r.get("flags") or ""
        key = (r["src"], r.get("sport"), r["dst"], r.get("dport"))
        seq = r.get("seq") or 0
        if "S" in fl:
            self.reasm.syn(key, seq, r["ts"], want=2 if "A" in fl else 1)
            return None
        res = None
        if payload:
            want = 1
            if looks_like_tls_handshake(payload) and payload[5:6] == b"\x02":
                want = 2
            res = self.reasm.feed(key, seq, payload, r["ts"], want=want, fin="F" in fl or "R" in fl)
            if looks_like_tls_handshake(payload) or (r.get("tls") is not None):
                self._mark(r, "tls")
        elif ("F" in fl or "R" in fl) and self.reasm.track(key):
            res = self.reasm.feed(key, seq, b"", r["ts"], fin=True)
        if res is None:
            return None
        return self._tls_result(r, res, tags)

    def _tls_result(self, r, res, tags) -> dict:
        ev = {"ts": r["ts"], "kind": "TLS", "src": r["src"], "dst": r["dst"], "sport": r.get("sport"), "dport": r.get("dport"),
              "rec": r, "reassembly": {k: res.get(k) for k in ("status", "segments", "bytes", "reordered", "duplicates", "conflicts",
                                                                "multi_segment", "code", "reason")}}
        if res["status"] != "complete":
            self.c["reasm_failed"] += 1
            tags.add("reasm_fail")
            ev.update(status=FAILED, note=f"TCP 재조립 실패: {res['reason']}")
            self.sni_status[FAILED] += 1
            self.events.append(ev)
            r["enc"] = {"status": FAILED, "note": ev["note"]}
            return {"hello": None}
        self.c["reasm_ok"] += 1
        if res.get("multi_segment"):
            self.c["reasm_multi"] += 1
            tags.add("reasm_multi")
        if res.get("conflicts"):
            r["reasm_conflict"] = res["conflicts"]
            tags.add("reasm_conflict")
        h = res["hello"]
        if h["type"] == "server_hello":
            self.c["server_hello"] += 1
            if h.get("tls_version"):
                self.tls_versions[h["tls_version"] + " (서버 선택)"] += 1
            if h.get("hybrid"):
                self.c["pqc_negotiated"] += 1
                tags.add("pqc")
            ev.update(status=CONFIRMED if not h.get("error") else FAILED, hello=h,
                      note=f"서버가 {h.get('tls_version')}·키 교환 그룹 {h.get('group')}을(를) 골랐어요" + (" (PQC 하이브리드)" if h.get("hybrid") else ""))
            self.events.append(ev)
            r["enc"] = {"status": ev["status"], "server_hello": {k: h.get(k) for k in ("tls_version", "group", "hybrid", "hrr")}}
            return {"hello": None, "server": h}
        return {"hello": self._client_hello(r, h, ev, tags, "TLS")}

    def _client_hello(self, r, h, ev, tags, kind) -> dict:
        self.c["client_hello"] += 1
        self.c[f"client_hello_{kind.lower()}"] += 1
        view = sni_view(h)
        self.sni_status[view["status"]] += 1
        self.ech[view["ech"]] += 1
        if h.get("tls_version"):
            self.tls_versions[h["tls_version"]] += 1
            if h["tls_version"] == "TLS 1.3":
                tags.add("tls13")
        for a in h.get("alpn") or []:
            self.alpn[a] += 1
        if h.get("pqc"):
            self.c["pqc_offered"] += 1
            tags.add("pqc")
        if view["status"] == CONFIRMED:
            tags.add("sni_ok")
        elif view["ech"] in ("confirmed", "esni"):
            tags.add("ech")
        elif view["ech"] == "unconfirmed":
            tags.add("ech_ext")
        ev.update(status=view["status"] if not h.get("error") else FAILED, hello=h, sni=view, note=view["note"])
        self.events.append(ev)
        r["enc"] = {"status": ev["status"], "status_label": STATUS_KO[ev["status"]], "sni": view, "tls_version": h.get("tls_version"),
                    "alpn": h.get("alpn"), "groups": h.get("groups"), "key_share": [k["group"] for k in h.get("key_share") or []],
                    "pqc": h.get("pqc"), "hybrid": h.get("hybrid"), "ech": h.get("ech"), "kind": kind,
                    "reassembly": ev.get("reassembly")}
        self._annotate_text(r, view, h, kind)
        return h

    def _annotate_text(self, r, view, h, kind):
        name = view.get("real_sni") or view.get("observed_sni")
        bits = [kind, h.get("tls_version") or ""]
        if view["status"] == CONFIRMED:
            bits.append(f"SNI={name}")
        elif view["ech"] == "confirmed":
            bits.append(f"ECH 사용 · 공개 이름={view['outer_sni']} (실제 도메인 암호화)")
        elif view["ech"] == "unconfirmed":
            bits.append(f"SNI={name} [ECH 확장: 실제 도메인인지 확정 불가]")
        if h.get("alpn"):
            bits.append("ALPN=" + ",".join(h["alpn"]))
        if h.get("hybrid"):
            bits.append("PQC 하이브리드 키 교환 제안")
        txt = " ".join(b for b in bits if b)
        if r.get("info") and txt not in r["info"]:
            r["info"] = f"{r['info']} · {txt}"
        if view["status"] == CONFIRMED and name:
            r["friendly"] = f"{name} 사이트에 암호화 연결을 시작해요 ({kind}{', HTTP/3' if kind == 'QUIC' and 'h3' in (h.get('alpn') or []) else ''})"
        elif view["ech"] == "confirmed":
            r["friendly"] = f"암호화 연결을 시작해요 · 실제 사이트 이름은 ECH로 숨겨져 있어요 ({kind})"
        elif view["ech"] == "unconfirmed" and name:
            r["friendly"] = f"{name}(으)로 보이는 암호화 연결을 시작해요 · ECH 확장이 있어 실제 도메인인지 확정할 수 없어요 ({kind})"

    def _udp(self, r, payload, tags) -> dict | None:
        sp, dp = r.get("sport"), r.get("dport")
        if not (sp in QUIC_PORTS or dp in QUIC_PORTS) and not (payload[0] & 0xC0 == 0xC0 and len(payload) >= 1200):
            return None
        long_hdr = bool(payload[0] & 0x80)
        if not long_hdr:
            return None                               # 1-RTT: 흐름이 이미 QUIC 으로 표시돼 있으면 위에서 집계
        results = self.quic.datagram(payload, r["ts"], flow=(r["src"], sp, r["dst"], dp))
        if not results and (payload[0] & 0x40):
            self._mark(r, "quic")
        out = None
        for q in results:
            self._mark(r, "quic")
            ev = {"ts": r["ts"], "kind": "QUIC", "src": r["src"], "dst": r["dst"], "sport": sp, "dport": dp, "rec": r, "quic": {
                k: q.get(k) for k in ("event", "version", "dcid", "scid", "initial_packets", "application", "app_status")}}
            if q["event"] == "client_hello":
                self.c["quic_hello"] += 1
                if q["application"] == "HTTP/3":
                    self.c["http3"] += 1
                    tags.add("h3")
                self._client_hello(r, q["client_hello"], ev, tags, "QUIC")
                r["enc"]["quic"] = ev["quic"]
                out = q
            elif q["event"] == "server_hello":
                h = q["server_hello"]
                if h.get("hybrid"):
                    self.c["pqc_negotiated"] += 1
                    tags.add("pqc")
                if h.get("tls_version"):
                    self.tls_versions[h["tls_version"] + " (서버 선택)"] += 1
                ev.update(status=CONFIRMED, hello=h, note=f"QUIC 서버가 키 교환 그룹 {h.get('group')}을(를) 골랐어요" + (" (PQC 하이브리드)" if h.get("hybrid") else ""))
                self.events.append(ev)
            else:
                self.c[f"quic_{q['event']}"] += 1
                if q["status"] == FAILED:
                    self.sni_status[FAILED] += 1
                    tags.add("quic_fail")
                ev.update(status=q["status"], note=q["note"])
                self.events.append(ev)
                r["enc"] = {"status": q["status"], "status_label": STATUS_KO[q["status"]], "note": q["note"], "kind": "QUIC"}
        return out

    def tick(self, now: float):
        """주기적 정리: 메워지지 않은 TCP 빈틈·QUIC CRYPTO 누락 → 분석 실패로 기록."""
        for res in self.reasm.expire(now):
            self.c["reasm_failed"] += 1
            self.sni_status[FAILED] += 1
            self.events.append({"ts": now, "kind": "TLS", "status": FAILED, "note": f"TCP 재조립 실패: {res['reason']}",
                                "reassembly": {k: res.get(k) for k in ("status", "segments", "code", "reason")}})
        for q in self.quic.pending_incomplete(now):
            self.sni_status[FAILED] += 1
            self.events.append({"ts": now, "kind": "QUIC", "status": FAILED, "note": q["note"], "quic": {"event": q["event"], "dcid": q["dcid"]}})

    # ───────────── 화면용 ─────────────
    def snapshot(self) -> dict:
        hello = self.c["client_hello"]
        sni_ok = self.sni_status[CONFIRMED]
        attempts = sum(self.sni_status.values())
        return {
            "protocol_bytes": dict(self.proto_bytes),
            "tls_versions": dict(self.tls_versions.most_common()),
            "alpn": dict(self.alpn.most_common(10)),
            "handshakes": {"client_hello": hello, "tls": self.c["client_hello_tls"], "quic": self.c["client_hello_quic"],
                           "server_hello": self.c["server_hello"]},
            "sni": {"attempts": attempts, "confirmed": sni_ok, "estimated": self.sni_status[ESTIMATED], "limited": self.sni_status[LIMITED],
                    "failed": self.sni_status[FAILED],
                    # 추출 성공률: ClientHello 를 끝까지 읽어 SNI 필드(또는 없음)를 확인한 비율 — 재조립·복호화 실패만 실패로 셈
                    "success_rate": round((attempts - self.sni_status[FAILED]) / attempts, 4) if attempts else None,
                    # 실제 도메인 확정률: ECH 확장이 없어 보이는 이름이 실제 접속 도메인이라고 확정할 수 있는 비율
                    "real_domain_rate": round(sni_ok / attempts, 4) if attempts else None},
            "ech": {"none": self.ech["none"], "unconfirmed": self.ech["unconfirmed"], "confirmed": self.ech["confirmed"], "esni": self.ech["esni"],
                    "configs_seen_in_dns": self.c["ech_configs_seen"]},
            "pqc": {"offered": self.c["pqc_offered"], "negotiated": self.c["pqc_negotiated"]},
            "reassembly": {"complete": self.c["reasm_ok"], "multi_segment": self.c["reasm_multi"], "failed": self.c["reasm_failed"],
                           "fail_reasons": dict(self.reasm.fail_reasons), "conflicts": self.reasm.stats["conflicts"],
                           "active": len(self.reasm.streams)},
            "quic": {**self.quic.stats, "http3": self.c["http3"]},
            "dns": self.dns.snapshot(),
            "opaque": {"bytes": self.bytes_opaque, "total": self.bytes_total,
                       "share": round(self.bytes_opaque / self.bytes_total, 4) if self.bytes_total else None},
        }

    def recent(self, kind: str | None = None, status: str | None = None, limit: int = 100) -> list[dict]:
        out = []
        for ev in reversed(self.events):
            if kind and ev.get("kind") != kind:
                continue
            if status and ev.get("status") != status:
                continue
            e = {k: v for k, v in ev.items() if k != "rec"}
            rec = ev.get("rec") or {}
            e["packet_id"] = rec.get("id")
            e["status_label"] = STATUS_KO.get(e.get("status"), e.get("status"))
            out.append(e)
            if len(out) >= limit:
                break
        return out
