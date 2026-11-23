"""패킷 무결성 탐지 — 체크섬 오류, TCP 주입(RST·데이터), UDP 재전송(리플레이).

팀 계획(UDP 체크섬 처리, 시퀀스 번호 검증·중복 차단, 비트 변조·재전송 방어)을 '관찰자' 입장에서 구현한다.
NetCare 는 패킷을 고치거나 버리지 않고, 수신 패킷에서 다음 징후를 찾아 알린다.

| 유형 | 판단 근거 | 확실성 |
|---|---|---|
| checksum_error | 수신 패킷의 IP 헤더·TCP·UDP·ICMP 체크섬 불일치 (비트 변조·손상) | suspected |
| tcp_injection  | 연결 상태(SEQ·ACK·FIN)와 어긋난 RST·데이터. TTL 차이는 상태 불일치와 겹칠 때만 징후로 셈 (정확한 SEQ 의 종료 RST 는 정상) | suspected |
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
        self.udp_last: dict[tuple, float] = {}  # (흐름, 식별자) → 마지막 관측 (오래된 흐름 정리)
        self._housekeep_at = None

    def _sec(self, ts: float) -> _Sec:
        s = int(ts)
        b = self.secs.get(s)
        if b is None:
            b = self.secs[s] = _Sec()
        return b

    # ───────────────────────── 관측 ─────────────────────────
    def observe(self, r: dict):
        if r.get("direction") == "up":
            self._observe_out(r)        # 내가 보낸 TCP 의 다음 순서 번호만 기록 (상대 RST 의 ACK 검증용)
            return
        if r.get("direction") not in ("down", "other"):
            return                      # 내부 통신은 제외
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

    def _observe_out(self, r: dict):
        if r.get("proto") != "TCP" or r.get("seq") is None:
            return
        st = self.flows.get((r.get("dst"), r.get("dport"), r.get("src"), r.get("sport")))
        if st is not None:
            fl = r.get("flags") or ""
            end = (r["seq"] + (r.get("payload_len") or 0) + ("S" in fl) + ("F" in fl)) % SEQ_MOD
            if st["my_nxt"] is None or _seq_dist(end, st["my_nxt"]) > 0:
                st["my_nxt"] = end

    def _observe_tcp(self, r: dict, ts: float, b: _Sec):
        """연결 상태(순서 번호·FIN·RST)와 TTL 을 함께 본다. TTL 차이만으로는 주입으로 세지 않는다.

        실측 오탐: 로드밸런서(34.149.66.165)가 FIN 이후 늦게 온 내 데이터에 RST 로 답하면서 TTL 이 108(평소 116)이었다.
        그 RST 의 SEQ 는 정확히 예상값(FIN+1)이었다 → 상태와 맞는 정상 종료. 이제는 이런 RST 를 징후로 세지 않는다.
        """
        cfg = self.det.cfg
        key = (r["src"], r.get("sport"), r.get("dst"), r.get("dport"))
        fl = r.get("flags") or ""
        ttl, seq, plen = r.get("ttl"), r.get("seq"), r.get("payload_len") or 0
        st = self.flows.get(key)
        if st is None:
            if len(self.flows) >= self.MAX_FLOWS:
                return
            st = self.flows[key] = {"ttls": deque(maxlen=8), "nxt": None, "last": ts, "rst": None, "after_rst": False,
                                    "fin": False, "my_nxt": None, "rst_hold": None, "dev_data": None}
        st["last"] = ts
        mode = Counter(st["ttls"]).most_common(1)[0][0] if len(st["ttls"]) >= 3 else None
        ttl_dev = mode is not None and ttl is not None and abs(ttl - mode) >= cfg.inject_ttl_delta
        flow_txt = f"{r['src']}:{r.get('sport')} → {r.get('dst')}:{r.get('dport')}"
        if "R" in fl:
            self._on_rst(st, r, ts, b, flow_txt, ttl_dev, mode)
            return                      # RST 의 TTL·SEQ 는 기준 학습에 넣지 않는다
        hold = st["rst_hold"]
        if hold and ts - hold[0] > 2.0:
            st["rst_hold"] = hold = None
        if plen > 0:
            dist = _seq_dist(seq, st["nxt"]) if (seq is not None and st["nxt"] is not None) else 0
            after_rst = st["rst"] is not None and ts - st["rst"] <= 2.0 and "S" not in fl
            if ttl_dev and len(st["ttls"]) >= 5:
                # TTL 이 다른 데이터: 연결 상태와 어긋날 때만 징후 (RST 뒤 데이터 · 이미 받은 위치와 겹침 · 순서 창 밖)
                if after_rst or dist < 0 or abs(dist) > cfg.inject_seq_window:
                    b.inject.append(("data_ttl", flow_txt, f"TTL {ttl} (평소 {mode})"))
                    if after_rst and not st["after_rst"]:
                        st["after_rst"] = True
                        b.inject.append(("data_after_rst", flow_txt, "RST 뒤에도 같은 쪽에서 데이터가 계속 옴"))
                    return              # 의심 패킷은 기준에 넣지 않는다
                # 순서대로 이어지는 데이터의 TTL 변화(경로 변경 등)는 기록만 하고, 정상 TTL 패킷이 같은 위치를 다시 보내면 경합으로 본다
                st["dev_data"] = (seq, (seq + plen) % SEQ_MOD, ts, ttl, mode)
            elif st["dev_data"] and seq is not None:
                dseq, dend, dts, dttl, dmode = st["dev_data"]
                if ts - dts <= 2.0 and _seq_dist(seq, dend) < 0 and _seq_dist((seq + plen) % SEQ_MOD, dseq) > 0:
                    # TTL 이 다른 데이터가 먼저 오고, 같은 위치를 평소 TTL 로 다시 받음 → 경로 위에서 끼워 넣은 데이터와 진짜 데이터의 경합
                    b.inject.append(("data_ttl", flow_txt, f"TTL {dttl} 데이터가 먼저 온 뒤 같은 위치를 평소 TTL {ttl} 로 다시 받음"))
                    st["dev_data"] = None
                elif ts - dts > 2.0:
                    st["dev_data"] = None
            if after_rst and not st["after_rst"]:
                st["after_rst"] = True
                b.inject.append(("data_after_rst", flow_txt, "RST 뒤에도 같은 쪽에서 데이터가 계속 옴"))
                if hold:                # 앞서 보류한 'TTL 다른 정확한 RST' 가 이제 상태와 어긋남이 확인됨
                    b.inject.append(("rst_ttl", flow_txt, hold[1]))
                    st["rst_hold"] = None
        if "F" in fl:
            st["fin"] = True
        if ttl is not None:
            st["ttls"].append(ttl)
        if seq is not None:
            end = (seq + plen + (1 if "S" in fl else 0) + (1 if "F" in fl else 0)) % SEQ_MOD
            if st["nxt"] is None or _seq_dist(end, st["nxt"]) > 0:
                st["nxt"] = end

    def _on_rst(self, st, r, ts, b, flow_txt, ttl_dev, mode):
        cfg = self.det.cfg
        seq, ack, ttl = r.get("seq"), r.get("ack"), r.get("ttl")
        fl = r.get("flags") or ""
        exp = st["nxt"]
        ttl_txt = f"TTL {ttl} (평소 {mode})"
        if exp is not None and seq:
            dist = _seq_dist(seq, exp)
            if abs(dist) > cfg.inject_seq_window:
                b.inject.append(("rst_seq", flow_txt, f"SEQ {seq} (예상 {exp})"))
                if ttl_dev:
                    b.inject.append(("rst_ttl", flow_txt, ttl_txt))
            elif abs(dist) <= 1:
                # 순서 번호가 정확한 RST. 상대가 이미 FIN 을 보냈다면 정상 종료 과정 → 징후 아님.
                # FIN 없이 TTL 만 다르면(로드밸런서 유휴 끊기와 경로 위 주입 모두 가능) 보류했다가,
                # 2초 안에 같은 쪽 데이터가 이어지거나 다른 SEQ 의 RST 가 또 오면 그때 징후로 센다.
                if ttl_dev and not st["fin"]:
                    hold = st["rst_hold"]
                    if hold and ts - hold[0] <= 2.0 and hold[2] != seq:
                        b.inject.append(("rst_ttl", flow_txt, hold[1]))
                        b.inject.append(("rst_ttl", flow_txt, ttl_txt + " · 서로 다른 SEQ 의 RST 반복"))
                        st["rst_hold"] = None
                    elif not hold:
                        st["rst_hold"] = (ts, ttl_txt, seq)
            elif ttl_dev:
                # 수신 창 안이지만 정확하지 않은 SEQ + 다른 TTL → 두 증거가 겹침
                b.inject.append(("rst_ttl", flow_txt, ttl_txt + f" · SEQ {seq} (예상 {exp})"))
        if "A" in fl and ack and st["my_nxt"] is not None:
            # 내가 보낸 적 없는 위치를 ACK 하거나 너무 오래된 위치를 ACK 하는 RST
            if _seq_dist(ack, st["my_nxt"]) > 1 or _seq_dist(st["my_nxt"], ack) > cfg.inject_seq_window:
                b.inject.append(("rst_ack", flow_txt, f"ACK {ack} (내가 보낸 다음 위치 {st['my_nxt']})"))
        st["rst"] = ts

    def _observe_udp(self, r: dict, b: _Sec):
        dst = r.get("dst") or ""
        try:
            da = ipaddress.ip_address(dst)
            if da.is_multicast or dst.endswith(".255") or dst == "255.255.255.255":
                return      # 방송·멀티캐스트 탐색 패킷은 같은 내용을 반복하는 게 정상 (실측: 방송 탐색 패킷을 RTP 로 오인)
        except ValueError:
            pass
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
        self.udp_last[k] = r.get("ts") or time.time()
        seen = self.udp_set[k]
        if seq in seen:
            b.replay.append((f"{flow[0]}:{flow[1]} → {flow[2]}:{flow[3]}", proto, seq[0] if isinstance(seq, tuple) else seq))
            return
        dq.append(seq)
        seen.add(seq)
        if len(dq) > 512:
            seen.discard(dq.popleft())

    # ───────────────────────── 정리 ─────────────────────────
    def maybe_housekeep(self, now: float):
        """장시간 실행: 30초마다 2분 넘게 조용한 TCP 흐름, 5분 넘게 조용한 UDP 순서 번호 흐름을 지운다.
        (예전: UDP 흐름은 지우지 않아 상한 20000 에 닿으면 새 흐름 검사를 조용히 멈췄음)"""
        if self._housekeep_at is not None and 0 <= now - self._housekeep_at < 30:
            return
        self._housekeep_at = now
        self.flows = {k: v for k, v in self.flows.items() if now - v["last"] < 120}
        for k in [k for k, t in self.udp_last.items() if now - t > 300]:
            self.udp_last.pop(k, None)
            self.udp_seen.pop(k, None)
            self.udp_set.pop(k, None)
        for k in [k for k in self.secs if k < int(now) - 60]:
            del self.secs[k]

    # ───────────────────────── 평가 ─────────────────────────
    def evaluate(self, now: float, W: int) -> list[dict]:
        end = int(now)
        for k in [k for k in self.secs if k < end - max(W, 10) - 5]:
            del self.secs[k]
        if len(self.flows) > self.MAX_FLOWS * 0.8:
            self.flows = {k: v for k, v in self.flows.items() if now - v["last"] < 120}
        self.maybe_housekeep(now)
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
