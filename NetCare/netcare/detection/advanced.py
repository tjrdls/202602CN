"""확장 탐지 규칙: 스푸핑 의심 + 패킷 기반 연결 품질 진단.

기존 Detector 가 이 클래스를 포함해 같은 observe()/evaluate() 흐름으로 호출한다.
모든 결과는 '수동 관찰(패킷만 보고 판단)'의 한계를 가진다. 그래서 확정할 수 없는 항목은
evidence["certainty"] 에 'suspected'(의심)로 표시하고 제목에도 '의심'을 붙인다.

| 유형 | 판단 근거 | 확실성 |
|---|---|---|
| arp_spoof | 같은 IP 에 서로 다른 MAC 이 짧은 시간에 나타남(특히 게이트웨이), 요청 없는 ARP 응답 반복 | likely |
| ip_spoof_suspect | 내 IP 를 출발지로 한 외부 프레임, LAN IP 와 학습된 MAC 불일치, 예약 주소 출발지, TTL 급변, 요청한 적 없는 SYN-ACK(백스캐터) | suspected |
| dns_spoof_suspect | 같은 질의에 서로 다른 응답 2개(경합 위조), 질의하지 않은 서버의 응답, DNS 서버 MAC 불일치 | suspected |
| latency_rise | 핸드셰이크·DNS 왕복 시간 중앙값이 기준과 평소의 2배+50ms 이상 | measured |
| jitter_high | 같은 상대에 대한 연속 RTT 차이 평균 | measured |
| tcp_loss | TCP 재전송(같은 SEQ 재송신)과 3중 중복 ACK, 응답 없는 ping | measured |
| connection_failure | 이전에 연결되던 서버로 SYN 이 응답 없이 반복 또는 거부(RST) | measured |
| bandwidth_limit_suspect | 주요 흐름의 처리량이 평평하게 막히면서 RTT 가 늘어남(큐 적체) | suspected |
"""
from __future__ import annotations

import ipaddress
import statistics
import time
from collections import Counter, defaultdict, deque

from netcare.analysis import terms


def _is_bogon(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_loopback or a.is_multicast or a.is_reserved or (a.is_unspecified)


class _Sec:
    __slots__ = ("arp_conflicts", "arp_unsolicited", "arp_redirected", "spoof", "dns_events", "rtt",
                 "data_segs", "retrans", "dupack3", "icmp_req", "icmp_unanswered", "syn_to", "synack_from",
                 "rst_from", "flow_bytes", "proto_cnt", "big_icmp", "big_dns", "nx_names")

    def __init__(self):
        self.arp_conflicts: list = []        # (ip, old_mac, new_mac)
        self.arp_unsolicited = Counter()     # mac → 요청 없는 ARP 응답 수
        self.arp_redirected = Counter()      # 의심 MAC 으로 보낸 내 프레임 수
        self.spoof: list = []                # (kind, ip, mac)
        self.dns_events: list = []           # (kind, qname, detail)
        self.rtt: list = []                  # (ts, peer, ms)
        self.data_segs = 0
        self.retrans = 0
        self.dupack3 = 0
        self.icmp_req = 0
        self.icmp_unanswered = 0
        self.syn_to = Counter()              # (dst, dport) → 내가 보낸 SYN
        self.synack_from = Counter()         # (src, sport) → 받은 SYN-ACK
        self.rst_from = Counter()
        self.flow_bytes = Counter()          # 흐름 → 바이트
        self.proto_cnt = Counter()           # 프로토콜별 패킷 수 (비율 이상 탐지)
        self.big_icmp = 0                    # 대형 ICMP 패킷 수
        self.big_dns = 0                     # 대형 DNS 패킷 수
        self.nx_names = Counter()            # NXDOMAIN 응답을 받은 도메인 → 횟수


class AdvancedDetector:
    def __init__(self, det):
        self.det = det            # 상위 Detector (cfg, local_ips, local_macs, gateway_ip 참조)
        self.secs: dict[int, _Sec] = {}
        self.arp_seen: dict[str, dict[str, float]] = defaultdict(dict)   # ip → {mac: 마지막 시각}
        self.arp_pending: dict[str, float] = {}                           # 누군가 물어본 IP → 시각
        self.ttl_hist: dict[tuple, Counter] = {}   # (출발지, 프로토콜) → TTL 분포
        self.out_syn: dict[tuple, float] = {}       # 내가 보낸 SYN 흐름 → 시각
        self.syn_count: Counter = Counter()          # 흐름별 SYN 횟수 (재전송된 SYN 은 RTT 표본 제외: Karn)
        self.in_synack_for_server: dict[tuple, float] = {}  # 내가 서버일 때 SYN-ACK 보낸 시각
        self.dns_q: dict[tuple, tuple] = {}          # (id, client) → (server, qname, ts)
        self.dns_resp: dict[tuple, tuple] = {}       # (id, client, qname) → (answers, ts, server)
        self.dns_server_mac: dict[str, str] = {}
        self.seqs: dict[tuple, deque] = {}           # 흐름 → 최근 데이터 SEQ
        self.last_ack: dict[tuple, list] = {}        # 흐름 → [ack, 연속 횟수]
        self.icmp_pending: dict[tuple, float] = {}
        self.target_ok: dict[tuple, float] = {}      # (dst, dport) → 마지막 연결 성공 시각
        self.fail_streak: dict[tuple, list] = {}     # (dst, dport) → [마지막 성공 이후 SYN 수, 마지막 SYN 시각, RST 수]
        self.rtt_base = None                         # 평소 RTT 중앙값 (EWMA)
        self.proto_base: dict[str, float] = {}       # 프로토콜 → 평소 비율 (EWMA, 1초 단위 학습)
        self.proto_learned = 0                       # 학습한 초 수
        self._proto_last_sec = None
        self.jit_base = None
        self.rtt_learned = 0

    # ───────────────────────── 관측 ─────────────────────────
    def _sec(self, ts: float) -> _Sec:
        s = int(ts)
        b = self.secs.get(s)
        if b is None:
            b = self.secs[s] = _Sec()
        return b

    def observe(self, r: dict):
        ts = r["ts"] or time.time()
        b = self._sec(ts)
        lips, lmacs = self.det.local_ips, self.det.local_macs
        src, dst, smac, proto = r["src"], r["dst"], r.get("src_mac"), r["proto"]

        b.proto_cnt[proto or "OTHER"] += 1
        pl0 = r.get("payload_len") or 0
        if r.get("dns_id") is not None:
            if pl0 >= self.det.cfg.size_anomaly_bytes:
                b.big_dns += 1
            if r.get("dns_qr") == 1 and r.get("dns_rcode") == 3 and r.get("dns_qname") and dst in lips:
                b.nx_names[r["dns_qname"]] += 1
        elif proto == "ICMP" and pl0 >= self.det.cfg.size_anomaly_bytes:
            b.big_icmp += 1
        if proto == "ARP":
            self._observe_arp(r, ts, b)
            return

        # 내가 의심 MAC 으로 보낸 프레임 (ARP 스푸핑으로 트래픽이 가로채지고 있는지)
        if r.get("dst_mac") and smac in lmacs and self._is_suspicious_mac(r["dst_mac"], ts):
            b.arp_redirected[r["dst_mac"]] += 1

        if src and r.get("ip_version"):
            self._observe_spoof(r, ts, b)

        if proto == "TCP":
            self._observe_tcp(r, ts, b)
        elif proto in ("ICMP",):
            it = r.get("icmp_type")
            if it == 8 and src in lips:
                b.icmp_req += 1
                if len(self.icmp_pending) < 5000:
                    self.icmp_pending[(dst, r.get("seq"), int(ts * 10))] = ts
            elif it == 0 and dst in lips:
                for k in [k for k in self.icmp_pending if k[0] == src][:1]:
                    del self.icmp_pending[k]
        if r.get("dns_id") is not None:
            self._observe_dns(r, ts, b)

    def _in_local_net(self, ip: str) -> bool:
        nets = self.det.local_nets
        if not nets:
            return True   # 서브넷 정보를 모르면 모든 주소를 대상으로
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in nets)

    def _observe_arp(self, r, ts, b):
        ip, mac, op = r["src"], r.get("arp_hwsrc") or r.get("src_mac"), r.get("arp_op")
        if not ip or ip == "0.0.0.0" or not mac:
            return  # ARP 프로브(주소 충돌 검사)는 제외
        if not self._in_local_net(ip):
            return  # 내 서브넷 밖 주소를 주장하는 ARP 는 판단하지 않음 (기본 IP 를 그대로 쓰는 장비 등, 실측 오탐)
        if op == 1:
            self.arp_pending[r["dst"]] = ts
        elif op == 2:
            asked = self.arp_pending.get(ip)
            if asked is None or ts - asked > 3:
                b.arp_unsolicited[mac] += 1
        seen = self.arp_seen[ip]
        for old_mac, t in list(seen.items()):
            if old_mac != mac and ts - t <= 120:
                b.arp_conflicts.append((ip, old_mac, mac))
        seen[mac] = ts
        if len(seen) > 8:
            for m, _ in sorted(seen.items(), key=lambda kv: kv[1])[:-8]:
                del seen[m]

    def _is_suspicious_mac(self, mac: str, ts: float) -> bool:
        """최근 ARP 충돌에서 새로 등장한 MAC 인가."""
        for s in range(int(ts) - self.det.cfg.window_sec, int(ts) + 1):
            b = self.secs.get(s)
            if b and any(c[2] == mac for c in b.arp_conflicts):
                return True
        return False

    def _observe_spoof(self, r, ts, b):
        src, smac, lips, lmacs = r["src"], r.get("src_mac"), self.det.local_ips, self.det.local_macs
        # 내 MAC 을 모르면(루프백·외부 pcap 등) MAC 기반 판단은 하지 않고 IP 방향으로만 본다
        mac_known = bool(lmacs) and bool(smac)
        inbound = (smac not in lmacs) if mac_known else (r["dst"] in lips and src not in lips)
        if not inbound:
            if r["proto"] == "TCP" and "S" in (r.get("flags") or "") and "A" not in (r.get("flags") or ""):
                if len(self.out_syn) < 50000:
                    self.out_syn[(src, r["sport"], r["dst"], r["dport"])] = ts
            return
        # ① 내 주소가 출발지인데 다른 장치의 프레임 (내 MAC 을 알 때만 판단 가능)
        if src in lips and mac_known:
            b.spoof.append(("own_ip", src, smac))
            return
        # ② 예약/특수 주소가 출발지 (DHCP 의 0.0.0.0 은 제외)
        if _is_bogon(src) and not (src == "0.0.0.0" and r.get("dport") in (67, 547)):
            b.spoof.append(("bogon", src, smac))
            return
        # ③ LAN 장치 IP 인데 ARP 로 학습한 MAC 과 다른 프레임
        seen = self.arp_seen.get(src)
        if mac_known and seen and len(seen) == 1 and self._in_local_net(src) and smac not in seen:
            # 같은 IP 에 MAC 이 여럿이면(충돌·이중화) 어느 쪽이 맞는지 알 수 없으므로 판단하지 않음
            gw = self.det.gateway_ip
            if src != gw:
                b.spoof.append(("lan_mac_mismatch", src, smac))
                return
        # ④ 같은 출발지의 평소 TTL 과 크게 다름
        # 프로토콜별로 따로 본다: 같은 서버라도 TCP 와 UDP(QUIC)를 서로 다른 장비·스택이 처리해 TTL 이 다를 수 있다
        # (실측: Google 서버 TCP TTL 116~117, QUIC TTL 53~54 → 합쳐서 보면 '위조 의심' 오탐)
        ttl = r.get("ttl")
        if ttl is not None and terms.ip_scope(src) == "public":
            hk = (src, r.get("proto"))
            h = self.ttl_hist.get(hk)
            if h is None:
                if len(self.ttl_hist) < 20000:
                    self.ttl_hist[hk] = Counter({ttl: 1})
            else:
                total = sum(h.values())
                common, cnt = h.most_common(1)[0]
                if total >= 5 and cnt / total >= 0.8 and abs(ttl - common) > self.det.cfg.ttl_deviation:
                    b.spoof.append(("ttl", src, smac))
                else:
                    h[ttl] += 1
        # ⑤ 요청한 적 없는 SYN-ACK (누군가 내 주소를 위조해 공격하면 그 응답이 나에게 온다)
        fl = r.get("flags") or ""
        if r["proto"] == "TCP" and "S" in fl and "A" in fl and r["dst"] in lips:
            key = (r["dst"], r["dport"], src, r["sport"])
            if key not in self.out_syn:
                b.spoof.append(("backscatter", src, smac))

    def _observe_tcp(self, r, ts, b):
        src, dst, sp, dp = r["src"], r["dst"], r["sport"], r["dport"]
        fl = r.get("flags") or ""
        lips = self.det.local_ips
        flow = (src, sp, dst, dp)
        if "S" in fl and "A" not in fl:
            self.syn_count[flow] += 1
            if src in lips:
                b.syn_to[(dst, dp)] += 1
                self.out_syn[flow] = ts
                st = self.fail_streak.setdefault((dst, dp), [0, ts, 0])
                st[0] += 1
                st[1] = ts
        elif "S" in fl and "A" in fl:
            rev = (dst, dp, src, sp)
            if dst in lips:
                b.synack_from[(src, sp)] += 1
                t0 = self.out_syn.get(rev)
                if t0 is not None and self.syn_count.get(rev, 0) == 1 and ts >= t0:
                    b.rtt.append((ts, src, (ts - t0) * 1000))
                self.target_ok[(src, sp)] = ts
                self.fail_streak.pop((src, sp), None)
            elif src in lips:
                self.in_synack_for_server[flow] = ts
        elif "R" in fl:
            if dst in lips:
                b.rst_from[(src, sp)] += 1
                st = self.fail_streak.get((src, sp))
                if st:
                    st[2] += 1
        else:
            # 내가 서버일 때: SYN-ACK → 상대 ACK 까지가 RTT
            rev = (dst, dp, src, sp)
            t0 = self.in_synack_for_server.pop(rev, None)
            if t0 is not None and src not in lips and ts >= t0:
                b.rtt.append((ts, src, (ts - t0) * 1000))
        pl = r.get("payload_len") or 0
        b.flow_bytes[flow] += r["length"]
        if pl > 0 and "S" not in fl:
            b.data_segs += 1
            dq = self.seqs.get(flow)
            if dq is None:
                if len(self.seqs) > 20000:
                    self.seqs.clear()
                dq = self.seqs[flow] = deque(maxlen=400)
            if r["seq"] in dq:
                b.retrans += 1
            else:
                dq.append(r["seq"])
        elif fl in ("A",) and pl == 0:
            la = self.last_ack.get(flow)
            if la and la[0] == r["ack"]:
                la[1] += 1
                if la[1] == 3:   # 같은 ACK 가 연속 3번 더 → 3중 중복 ACK (수신 측이 빠진 데이터를 알림)
                    b.dupack3 += 1
            else:
                if len(self.last_ack) > 20000:
                    self.last_ack.clear()
                self.last_ack[flow] = [r["ack"], 0]

    def _observe_dns(self, r, ts, b):
        lips = self.det.local_ips
        did, src, dst, qn = r["dns_id"], r["src"], r["dst"], r.get("dns_qname")
        if r.get("dns_qr") == 0:
            if src in lips and len(self.dns_q) < 20000:
                self.dns_q[(did, src)] = (dst, qn, ts)
            return
        if dst not in lips:
            return
        q = self.dns_q.get((did, dst))
        if q is not None:
            server, qname, t0 = q
            if src != server:
                b.dns_events.append(("wrong_server", qn, f"{server}에 물었는데 {src}가 응답"))
            elif qname == qn and ts >= t0 and (did, dst, qn) not in self.dns_resp:
                b.rtt.append((ts, src, (ts - t0) * 1000))
        smac = r.get("src_mac")
        if smac and terms.ip_scope(src) == "local":
            known = self.dns_server_mac.get(src)
            if known is None:
                self.dns_server_mac[src] = smac
            elif known != smac:
                b.dns_events.append(("server_mac", qn, f"{src}의 MAC이 {known} → {smac}"))
        ans = tuple(sorted(r.get("dns_answers") or ()))
        key = (did, dst, qn)
        prev = self.dns_resp.get(key)
        if prev is not None and ans and prev[0] and set(ans) != set(prev[0]) and ts - prev[1] <= 3:
            b.dns_events.append(("conflict", qn, f"{', '.join(prev[0][:2])} ↔ {', '.join(ans[:2])}"))
        if len(self.dns_resp) > 20000:
            self.dns_resp.clear()
        self.dns_resp[key] = (ans, ts, src)

    # ───────────────────────── 평가 ─────────────────────────
    def evaluate(self, now: float, W: int) -> list[dict]:
        cfg = self.det.cfg
        end = int(now)
        for k in [k for k in self.secs if k < end - max(W, 10) - 5]:
            del self.secs[k]
        for k, t in list(self.icmp_pending.items()):
            if now - t > 2:
                del self.icmp_pending[k]
                self._sec(now - 1).icmp_unanswered += 1
        if len(self.out_syn) > 20000:
            self.out_syn = {k: v for k, v in self.out_syn.items() if v >= now - 60}
            self.syn_count = Counter({k: v for k, v in self.syn_count.items() if k in self.out_syn})
        win = [self.secs[s] for s in range(end - W, end) if s in self.secs]
        if not win:
            return []
        out: list[dict] = []
        out += self._rule_arp(win, W)
        out += self._rule_ip_spoof(win, W)
        out += self._rule_dns_spoof(win, W)
        rtt_cands = self._rule_latency_jitter(win, W)
        out += rtt_cands
        out += self._rule_loss(win, W)
        out += self._rule_conn_fail(win, W, now)
        out += self._rule_bandwidth(win, W, end)
        out += self._rule_size(win, W)
        out += self._rule_nxdomain(win, W)
        shift = self._rule_proto_shift(win, W)
        out += shift
        self._learn_proto(end, bool(shift))
        return out

    # ── 비정상 패킷 크기 / 프로토콜 비율 / DNS 응답 이상 (모두 '정보' 등급, 의심 수준) ──
    def _rule_size(self, win, W):
        cfg = self.det.cfg
        icmp = sum(b.big_icmp for b in win)
        dns = sum(b.big_dns for b in win)
        out = []
        for kind, n, proto in (("ICMP", icmp, "ICMP"), ("DNS", dns, "UDP")):
            if n >= cfg.size_anomaly_min_count:
                out.append(dict(type="packet_size_anomaly", severity="info", src=None, dst=None, port=53 if kind == "DNS" else None, protocol=proto,
                                criterion=f"{W}초 동안 페이로드 {cfg.size_anomaly_bytes}바이트 이상인 {kind} 패킷 {cfg.size_anomaly_min_count}개 이상",
                                threshold=cfg.size_anomaly_min_count, measured=n,
                                evidence={"window_sec": W, "certainty": "suspected", "kind": kind, "count": n, "min_bytes": cfg.size_anomaly_bytes}))
        return out

    def _rule_nxdomain(self, win, W):
        cfg = self.det.cfg
        names = Counter()
        for b in win:
            names.update(b.nx_names)
        total = sum(names.values())
        if total < cfg.nxdomain_threshold or len(names) < cfg.nxdomain_min_names:
            return []
        return [dict(type="dns_nxdomain_surge", severity="info", src=None, dst=None, port=53, protocol="UDP",
                     criterion=f"{W}초 동안 존재하지 않는 도메인(NXDOMAIN) 응답 {cfg.nxdomain_threshold}건 이상 & 서로 다른 도메인 {cfg.nxdomain_min_names}개 이상",
                     threshold=cfg.nxdomain_threshold, measured=total,
                     evidence={"window_sec": W, "certainty": "suspected", "count": total, "distinct_names": len(names),
                               "samples": [n for n, _ in names.most_common(8)]})]

    def _rule_proto_shift(self, win, W):
        cfg = self.det.cfg
        if self.proto_learned < 60 or not self.proto_base:
            return []
        tot = Counter()
        for b in win:
            tot.update(b.proto_cnt)
        n = sum(tot.values())
        if n < cfg.proto_shift_min_pps * max(1, len(win)):
            return []
        out = []
        for proto in ("UDP", "ICMP", "OTHER"):
            share = tot.get(proto, 0) / n
            base = self.proto_base.get(proto, 0.0)
            if share - base >= cfg.proto_shift_delta:
                out.append(dict(type="proto_ratio_shift", severity="info", src=None, dst=None, port=None, protocol=proto,
                                criterion=f"{W}초 동안 {proto} 비율이 평소보다 {cfg.proto_shift_delta:.0%}p 이상 증가 (평균 {cfg.proto_shift_min_pps} PPS 이상일 때)",
                                threshold=round(base + cfg.proto_shift_delta, 3), measured=round(share, 3),
                                evidence={"window_sec": W, "certainty": "suspected", "proto": proto, "share": round(share, 3),
                                          "baseline_share": round(base, 3), "packets": n, "learned_sec": self.proto_learned}))
                break
        return out

    def _learn_proto(self, end: int, anomalous: bool):
        sec = end - 1
        if sec == self._proto_last_sec:
            return
        self._proto_last_sec = sec
        b = self.secs.get(sec)
        if not b or anomalous:
            return
        n = sum(b.proto_cnt.values())
        if n < 5:
            return
        a = 0.05
        for proto in ("TCP", "UDP", "ICMP", "OTHER"):
            share = b.proto_cnt.get(proto, 0) / n
            self.proto_base[proto] = share if proto not in self.proto_base else (1 - a) * self.proto_base[proto] + a * share
        self.proto_learned += 1

    def _rule_arp(self, win, W):
        conflicts = [c for b in win for c in b.arp_conflicts]
        unsolicited = Counter()
        redirected = Counter()
        for b in win:
            unsolicited.update(b.arp_unsolicited)
            redirected.update(b.arp_redirected)
        if not conflicts:
            return []
        by_ip = defaultdict(set)
        for ip, old, new in conflicts:
            by_ip[ip].update((old, new))
        gw = self.det.gateway_ip
        ip = gw if gw in by_ip else max(by_ip, key=lambda k: len(by_ip[k]))
        macs = sorted(by_ip[ip])
        new_macs = [c[2] for c in conflicts if c[0] == ip]
        suspect_mac = Counter(new_macs).most_common(1)[0][0]
        unsol = unsolicited.get(suspect_mac, 0)
        if len(conflicts) < 2 and unsol < 2:
            return []   # 한 번의 변경은 DHCP 재할당 등 정상일 수 있음
        sev = "danger" if ip == gw else "warning"
        return [dict(type="arp_spoof", severity=sev, src=None, dst=ip, port=None, protocol="ARP",
                     criterion=f"{W}초 동안 같은 IP에 서로 다른 MAC 주소가 반복해서 나타남 (2회 이상)",
                     threshold=2, measured=len(conflicts),
                     evidence={"window_sec": W, "certainty": "likely", "target_ip": ip, "is_gateway": ip == gw,
                               "macs": macs, "suspect_mac": suspect_mac, "conflicts": len(conflicts),
                               "unsolicited_replies": unsol, "redirected_frames": sum(redirected.values())})]

    def _rule_ip_spoof(self, win, W):
        ev = [e for b in win for e in b.spoof]
        th = self.det.cfg.spoof_min_indicators
        if len(ev) < th:
            return []
        kinds = Counter(k for k, _, _ in ev)
        macs = Counter(m for _, _, m in ev if m)
        ips = Counter(ip for _, ip, _ in ev)
        # 패킷만으로는 위조를 확정할 수 없으므로 '주의'를 넘기지 않는다
        return [dict(type="ip_spoof_suspect", severity="warning", src=None, dst=None, port=None, protocol=None,
                     criterion=f"{W}초 동안 출발지 위조 징후 {th}개 이상 (내 주소 도용·MAC 불일치·예약 주소·TTL 급변·요청 없는 응답)",
                     threshold=th, measured=len(ev),
                     evidence={"window_sec": W, "certainty": "suspected", "indicators": dict(kinds),
                               "sample_sources": [ip for ip, _ in ips.most_common(6)], "distinct_sources": len(ips),
                               "frame_macs": [m for m, _ in macs.most_common(3)]})]

    def _rule_dns_spoof(self, win, W):
        ev = [e for b in win for e in b.dns_events]
        th = self.det.cfg.dns_spoof_min_events
        if len(ev) < th:
            return []
        kinds = Counter(k for k, _, _ in ev)
        names = Counter(q for _, q, _ in ev if q)
        return [dict(type="dns_spoof_suspect", severity="warning",   # 확정 불가 → 최대 '주의' src=None, dst=None, port=53, protocol="DNS",
                     criterion=f"{W}초 동안 DNS 응답 위조 징후 {th}건 이상 (같은 질의에 다른 응답·엉뚱한 서버 응답·서버 MAC 변경)",
                     threshold=th, measured=len(ev),
                     evidence={"window_sec": W, "certainty": "suspected", "indicators": dict(kinds),
                               "names": [n for n, _ in names.most_common(5)], "examples": [d for _, _, d in ev[:3]]})]

    def _rule_latency_jitter(self, win, W):
        cfg = self.det.cfg
        samples = sorted((s for b in win for s in b.rtt), key=lambda x: x[0])
        out = []
        if not samples:
            return out
        med = statistics.median(ms for _, _, ms in samples)
        by_peer = defaultdict(list)
        for _, peer, ms in samples:
            by_peer[peer].append(ms)
        diffs = [abs(v[i] - v[i - 1]) for v in by_peer.values() for i in range(1, len(v))]
        # 중앙값 사용: 지연이 한 번 크게 바뀌는 '계단'(장애 시작·종료)은 차이 1개만 크므로 지터로 오인하지 않음 (벤치마크에서 발견)
        jit = statistics.median(diffs) if diffs else 0.0
        warm = self.rtt_learned >= 15 and self.rtt_base is not None
        anomalous = False
        if warm and len(samples) >= cfg.latency_min_samples and med >= cfg.latency_ms and med >= self.rtt_base * 2 + 50:
            anomalous = True
            out.append(dict(type="latency_rise", severity="danger" if med >= cfg.latency_ms * 3 else "warning",
                            src=None, dst=None, port=None, protocol=None,
                            criterion=f"왕복 시간(RTT) 중앙값 {cfg.latency_ms:g}ms 이상 & 평소의 2배+50ms 이상",
                            threshold=cfg.latency_ms, measured=round(med, 1),
                            evidence={"window_sec": W, "certainty": "measured", "median_ms": round(med, 1),
                                      "baseline_ms": round(self.rtt_base, 1), "samples": len(samples),
                                      "method": "TCP 핸드셰이크·DNS 응답 시간"}))
        if warm and len(diffs) >= cfg.jitter_min_samples and jit >= cfg.jitter_ms and jit >= (self.jit_base or 0) * 3 + 10:
            anomalous = True
            out.append(dict(type="jitter_high", severity="warning", src=None, dst=None, port=None, protocol=None,
                            criterion=f"같은 상대에 대한 연속 RTT 차이(중앙값) {cfg.jitter_ms:g}ms 이상 & 평소의 3배 이상",
                            threshold=cfg.jitter_ms, measured=round(jit, 1),
                            evidence={"window_sec": W, "certainty": "measured", "jitter_ms": round(jit, 1),
                                      "baseline_jitter_ms": round(self.jit_base or 0, 1), "pairs": len(diffs),
                                      "median_ms": round(med, 1), "min_ms": round(min(ms for *_, ms in samples), 1),
                                      "max_ms": round(max(ms for *_, ms in samples), 1)}))
        if not anomalous:   # 이상 구간은 기준선 학습에서 제외
            a = 0.1
            self.rtt_base = med if self.rtt_base is None else (1 - a) * self.rtt_base + a * med
            if diffs:
                self.jit_base = jit if self.jit_base is None else (1 - a) * self.jit_base + a * jit
            newest = win[-1].rtt if win else []
            self.rtt_learned += len(newest)
        return out

    def _rule_loss(self, win, W):
        cfg = self.det.cfg
        segs = sum(b.data_segs for b in win)
        events = sum(b.retrans + b.dupack3 for b in win)
        icmp_req = sum(b.icmp_req for b in win)
        icmp_lost = sum(b.icmp_unanswered for b in win)
        tcp_ratio = events / segs if segs else 0.0
        icmp_ratio = icmp_lost / icmp_req if icmp_req >= 4 else 0.0
        tcp_hit = segs >= cfg.loss_min_segments and tcp_ratio >= cfg.loss_ratio
        icmp_hit = icmp_req >= 4 and icmp_ratio >= 0.25
        if not (tcp_hit or icmp_hit):
            return []
        ratio = max(tcp_ratio if tcp_hit else 0, icmp_ratio if icmp_hit else 0)
        return [dict(type="tcp_loss", severity="danger" if ratio >= cfg.loss_ratio * 3 else "warning",
                     src=None, dst=None, port=None, protocol="TCP",
                     criterion=f"재전송·중복 ACK 비율 {cfg.loss_ratio:.0%} 이상 (데이터 {cfg.loss_min_segments}개 이상) 또는 ping 무응답 25% 이상",
                     threshold=cfg.loss_ratio, measured=round(ratio, 3),
                     evidence={"window_sec": W, "certainty": "measured", "data_segments": segs,
                               "retransmissions": sum(b.retrans for b in win), "triple_dup_acks": sum(b.dupack3 for b in win),
                               "tcp_loss_ratio": round(tcp_ratio, 3), "ping_sent": icmp_req, "ping_lost": icmp_lost})]

    def _rule_conn_fail(self, win, W, now):
        """마지막 성공 이후 연속으로 실패한 연결 시도 수로 판단 (오래된 성공 응답이 판단을 늦추지 않도록)."""
        cfg = self.det.cfg
        out = []
        if len(self.fail_streak) > 5000:
            self.fail_streak = {k: v for k, v in self.fail_streak.items() if now - v[1] <= 60}
        for target, (n, last_syn, refused) in sorted(self.fail_streak.items(), key=lambda kv: -kv[1][0])[:5]:
            if n < cfg.conn_fail_attempts or now - last_syn > W:
                continue
            last_ok = self.target_ok.get(target)
            if last_ok is None or now - last_ok > 300:
                continue   # 처음 접속하는 곳의 실패는 차단·오타일 수 있어 판단하지 않음
            out.append(dict(type="connection_failure", severity="warning", src=None, dst=target[0], port=target[1],
                            protocol="TCP",
                            criterion=f"이전에 연결되던 서버로 마지막 성공 이후 연결 요청 {cfg.conn_fail_attempts}회 이상이 연속 실패",
                            threshold=cfg.conn_fail_attempts, measured=n,
                            evidence={"window_sec": W, "certainty": "measured", "attempts": n, "refused_rst": refused,
                                      "mode": "거부(RST)" if refused else "응답 없음(시간 초과)",
                                      "last_success_ago_sec": round(now - last_ok, 1)}))
        return out

    def _rule_bandwidth(self, win, W, end):
        cfg = self.det.cfg
        total = Counter()
        for b in win:
            total.update(b.flow_bytes)
        if not total or self.rtt_base is None:
            return []
        # 방향을 합친 흐름 기준
        merged = Counter()
        for (s, sp, d, dp), v in total.items():
            key = tuple(sorted([(s, sp), (d, dp)]))
            merged[key] += v
        key, _ = merged.most_common(1)[0]
        series = []
        for s in range(end - W, end):
            b = self.secs.get(s)
            v = 0
            if b:
                for (a, ap, c, cp), x in b.flow_bytes.items():
                    if tuple(sorted([(a, ap), (c, cp)])) == key:
                        v += x
            series.append(v)
        active = [v for v in series if v > 0]
        if len(active) < cfg.bw_min_seconds:
            return []
        mean = statistics.fmean(active)
        if mean < 20_000:
            return []
        cv = statistics.pstdev(active) / mean
        samples = [ms for b in win for _, _, ms in b.rtt]
        if len(samples) < 3:
            return []
        med = statistics.median(samples)
        inflation = med - self.rtt_base
        if cv > cfg.bw_flat_cv or inflation < cfg.bw_rtt_inflation_ms:
            return []
        peer = [p for p in key if p[0] not in self.det.local_ips]
        return [dict(type="bandwidth_limit_suspect", severity="info", src=peer[0][0] if peer else None, dst=None,
                     port=peer[0][1] if peer else None, protocol="TCP",
                     criterion=f"주요 흐름 처리량 변동계수 {cfg.bw_flat_cv:g} 이하(일정하게 막힘) & RTT 평소보다 {cfg.bw_rtt_inflation_ms:g}ms 이상 증가",
                     threshold=cfg.bw_flat_cv, measured=round(cv, 3),
                     evidence={"window_sec": W, "certainty": "suspected", "throughput_bps": round(mean, 1),
                               "cv": round(cv, 3), "median_rtt_ms": round(med, 1), "baseline_rtt_ms": round(self.rtt_base, 1),
                               "rtt_inflation_ms": round(inflation, 1), "active_seconds": len(active)})]
