"""패킷 무결성 탐지 — 체크섬 오류, TCP 주입(RST·데이터), UDP 재전송(리플레이).

팀 계획(UDP 체크섬 처리, 시퀀스 번호 검증·중복 차단, 비트 변조·재전송 방어)을 '관찰자' 입장에서 구현한다.
NetCare 는 패킷을 고치거나 버리지 않고, 수신 패킷에서 다음 징후를 찾아 알린다.

| 유형 | 판단 근거 | 확실성 |
|---|---|---|
| checksum_error | 수신 패킷의 IP 헤더·TCP·UDP·ICMP 체크섬 불일치 (비트 변조·손상) | suspected |
| tcp_injection  | 같은 연결의 평소 TTL 과 다른 RST·데이터, 순서 번호(SEQ)가 크게 벗어난 RST, RST 이후에도 이어지는 데이터 | suspected |
| udp_replay     | RTP(통화)·설정한 UDP 프로토콜에서 같은 순서 번호가 다시 도착 (재전송 공격·중복) | suspected |

송신 패킷은 NIC 체크섬 오프로드 때문에 검사하지 않는다(파서가 수신 패킷에만 csum 을 채움).
"""
from __future__ import annotations

import ipaddress
import time
from collections import Counter, deque

SEQ_MOD = 1 << 32


def _seq_dist(a: int, b: int) -> int:
    """32비트 순서 번호 a - b 를 부호 있는 거리로."""
    d = (a - b) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_MOD // 2 else d


def _is_loopback(ip: str | None) -> bool:
    try:
        return ip is not None and ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def parse_seq_ports(items) -> dict[int, tuple[int, int]]:
    """설정 'udp_seq_ports' 항목("포트:오프셋:크기")을 {포트: (오프셋, 크기)} 로. 잘못된 항목은 건너뛴다."""
    out = {}
    for it in items or []:
        try:
            port, off, size = (int(x) for x in str(it).split(":"))
        except ValueError:
            continue
        if 0 < port < 65536 and off >= 0 and size in (1, 2, 4, 8) and off + size <= 16:
            out[port] = (off, size)
    return out


class _Sec:
    __slots__ = ("csum_bad", "csum_checked", "csum_layers", "inject", "replay")

    def __init__(self):
        self.csum_bad = Counter()       # 출발지 → 체크섬 틀린 수신 패킷 수
        self.csum_checked = Counter()   # 출발지 → 검사한 수신 패킷 수
        self.csum_layers = Counter()    # ip / TCP / UDP / ICMP
        self.inject: list = []          # (kind, flow, detail)
        self.replay: list = []          # (flow, proto, seq)


class IntegrityDetector:
    MAX_FLOWS = 20000

    def __init__(self, det):
        self.det = det
        self.secs: dict[int, _Sec] = {}
        self.flows: dict[tuple, dict] = {}      # (src, sport, dst, dport) → {ttls, nxt, last, rst}
        self.udp_seen: dict[tuple, deque] = {}  # (흐름, 식별자) → 최근 순서 번호
        self.udp_set: dict[tuple, set] = {}

    def _sec(self, ts: float) -> _Sec:
        s = int(ts)
        b = self.secs.get(s)
        if b is None:
            b = self.secs[s] = _Sec()
        return b

    # ───────────────────────── 관측 ─────────────────────────
    def observe(self, r: dict):
        if r.get("direction") not in ("down", "other"):
            return                      # 내가 보낸 패킷·내부 통신은 제외
        ts = r.get("ts") or time.time()
        src = r.get("src")
        if not src or _is_loopback(src):
            return
        b = self._sec(ts)
        cs = r.get("csum")
        if cs:
            b.csum_checked[src] += 1
            bad = [k for k, v in (("ip", cs.get("ip")), (cs.get("l4_proto") or "l4", cs.get("l4"))) if v is False]
            if bad:
                b.csum_bad[src] += 1
                b.csum_layers.update(bad)
        proto = r.get("proto")
        if r.get("reasm_conflict"):
            # TCP 재조립 중 같은 위치에 서로 다른 데이터가 온 경우 (주입·IDS 우회 시도 형태)
            b.inject.append(("overlap_conflict", f"{src}:{r.get('sport')} → {r.get('dst')}:{r.get('dport')}",
                             f"재조립 중 겹친 데이터 {r['reasm_conflict']}건의 내용이 서로 다름"))
        if proto == "TCP":
            self._observe_tcp(r, ts, b)
        elif proto == "UDP":
            self._observe_udp(r, b)

    def _observe_tcp(self, r: dict, ts: float, b: _Sec):
        cfg = self.det.cfg
        key = (r["src"], r.get("sport"), r.get("dst"), r.get("dport"))
        fl = r.get("flags") or ""
        ttl, seq, plen = r.get("ttl"), r.get("seq"), r.get("payload_len") or 0
        st = self.flows.get(key)
        if st is None:
            if len(self.flows) >= self.MAX_FLOWS:
                return
            st = self.flows[key] = {"ttls": deque(maxlen=8), "nxt": None, "last": ts, "rst": None, "after_rst": False}
        st["last"] = ts
        mode = Counter(st["ttls"]).most_common(1)[0][0] if len(st["ttls"]) >= 3 else None
        flow_txt = f"{r['src']}:{r.get('sport')} → {r.get('dst')}:{r.get('dport')}"
        if "R" in fl:
            if mode is not None and ttl is not None and abs(ttl - mode) >= cfg.inject_ttl_delta:
                b.inject.append(("rst_ttl", flow_txt, f"TTL {ttl} (평소 {mode})"))
            if st["nxt"] is not None and seq and abs(_seq_dist(seq, st["nxt"])) > cfg.inject_seq_window:
                b.inject.append(("rst_seq", flow_txt, f"SEQ {seq} (예상 {st['nxt']})"))
            st["rst"] = ts
            return                      # RST 의 TTL·SEQ 는 기준 학습에 넣지 않는다
        if plen > 0:
            if mode is not None and ttl is not None and len(st["ttls"]) >= 5 and abs(ttl - mode) >= cfg.inject_ttl_delta:
                b.inject.append(("data_ttl", flow_txt, f"TTL {ttl} (평소 {mode})"))
                return                  # 의심 패킷은 기준에 넣지 않는다
            if st["rst"] is not None and ts - st["rst"] <= 2.0 and "S" not in fl and not st["after_rst"]:
                st["after_rst"] = True
                b.inject.append(("data_after_rst", flow_txt, "RST 뒤에도 같은 쪽에서 데이터가 계속 옴"))
        if ttl is not None:
            st["ttls"].append(ttl)
        if seq is not None:
            end = (seq + plen + (1 if "S" in fl else 0) + (1 if "F" in fl else 0)) % SEQ_MOD
            if st["nxt"] is None or _seq_dist(end, st["nxt"]) > 0:
                st["nxt"] = end

    def _observe_udp(self, r: dict, b: _Sec):
        flow = (r["src"], r.get("sport"), r.get("dst"), r.get("dport"))
        ident = seq = None
        rtp = r.get("rtp")
        raw_ports = tuple(self.det.cfg.udp_seq_ports or ())
        if getattr(self, "_ports_key", None) != raw_ports:
            self._ports_key, self._ports = raw_ports, parse_seq_ports(raw_ports)
        ports = self._ports
        port_rule = ports.get(r.get("dport")) or ports.get(r.get("sport"))
        if port_rule and r.get("udp_head"):
            off, size = port_rule
            head = bytes.fromhex(r["udp_head"])
            if len(head) >= off + size:
                ident, seq, proto = ("cfg",), int.from_bytes(head[off:off + size], "big"), "설정 프로토콜"
        elif rtp:
            ident, seq, proto = ("rtp", rtp["ssrc"]), (rtp["seq"], rtp["ts"]), "RTP"
        if ident is None:
            return
        k = flow + ident
        dq = self.udp_seen.get(k)
        if dq is None:
            if len(self.udp_seen) >= self.MAX_FLOWS:
                return
            dq, self.udp_set[k] = self.udp_seen.setdefault(k, deque()), set()
        seen = self.udp_set[k]
        if seq in seen:
            b.replay.append((f"{flow[0]}:{flow[1]} → {flow[2]}:{flow[3]}", proto, seq[0] if isinstance(seq, tuple) else seq))
            return
        dq.append(seq)
        seen.add(seq)
        if len(dq) > 512:
            seen.discard(dq.popleft())

    # ───────────────────────── 평가 ─────────────────────────
    def evaluate(self, now: float, W: int) -> list[dict]:
        end = int(now)
        for k in [k for k in self.secs if k < end - max(W, 10) - 5]:
            del self.secs[k]
        if len(self.flows) > self.MAX_FLOWS * 0.8:
            self.flows = {k: v for k, v in self.flows.items() if now - v["last"] < 120}
        win = [self.secs[s] for s in range(end - W, end) if s in self.secs]
        if not win:
            return []
        return self._rule_checksum(win, W) + self._rule_injection(win, W) + self._rule_replay(win, W)

    def _rule_checksum(self, win, W):
        cfg = self.det.cfg
        bad, checked, layers = Counter(), Counter(), Counter()
        for b in win:
            bad.update(b.csum_bad)
            checked.update(b.csum_checked)
            layers.update(b.csum_layers)
        out = []
        for src, n in bad.most_common(3):
            total = checked.get(src, 0)
            ratio = n / total if total else 0
            if n < cfg.csum_min_bad or ratio < cfg.csum_bad_ratio:
                continue
            out.append(dict(type="checksum_error", severity="warning" if ratio >= 0.5 else "info", src=src, dst=None, port=None, protocol=None,
                            criterion=f"{W}초 동안 체크섬이 틀린 수신 패킷 {cfg.csum_min_bad}개 이상 & 그 출발지 패킷의 {cfg.csum_bad_ratio:.0%} 이상",
                            threshold=cfg.csum_min_bad, measured=n,
                            evidence={"window_sec": W, "certainty": "suspected", "bad": n, "checked": total, "ratio": round(ratio, 3),
                                      "layers": dict(layers)}))
        return out

    def _rule_injection(self, win, W):
        cfg = self.det.cfg
        ev = [e for b in win for e in b.inject]
        if len(ev) < cfg.inject_min_events:
            return []
        kinds = Counter(k for k, _, _ in ev)
        flows = sorted({f for _, f, _ in ev})
        return [dict(type="tcp_injection", severity="warning", src=None, dst=None, port=None, protocol="TCP",
                     criterion=f"{W}초 동안 TCP 주입 징후 {cfg.inject_min_events}건 이상 (평소와 다른 TTL의 RST·데이터, 순서 번호를 벗어난 RST, RST 뒤 데이터)",
                     threshold=cfg.inject_min_events, measured=len(ev),
                     evidence={"window_sec": W, "certainty": "suspected", "indicators": dict(kinds), "flows": flows[:5],
                               "distinct_flows": len(flows), "examples": [f"{f} · {d}" for _, f, d in ev[:5]]})]

    def _rule_replay(self, win, W):
        cfg = self.det.cfg
        per = Counter()
        sample: dict[str, list] = {}
        proto_of = {}
        for b in win:
            for flow, proto, seq in b.replay:
                per[flow] += 1
                proto_of[flow] = proto
                sample.setdefault(flow, []).append(seq)
        out = []
        for flow, n in per.most_common(2):
            if n < cfg.udp_replay_min:
                break
            out.append(dict(type="udp_replay", severity="warning", src=flow.split(":")[0], dst=None, port=None, protocol="UDP",
                            criterion=f"{W}초 동안 같은 흐름에서 이미 받은 순서 번호가 {cfg.udp_replay_min}번 이상 다시 도착",
                            threshold=cfg.udp_replay_min, measured=n,
                            evidence={"window_sec": W, "certainty": "suspected", "flow": flow, "protocol": proto_of[flow],
                                      "duplicates": n, "sample_seq": sorted(set(sample[flow]))[:10]}))
        return out
