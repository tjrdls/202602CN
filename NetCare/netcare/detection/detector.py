"""이상 트래픽 탐지기.

구조
- 패킷마다 observe() 로 초 단위 버킷에 카운트를 쌓는다.
- 1초마다 evaluate(now) 가 최근 window_sec 초를 합산해 규칙을 검사한다.
- ④ 트래픽 급증은 EWMA(지수가중이동평균) 기준선과 z-score 로 판단하는 통계 탐지이며,
  기준선 학습(warmup) 전에는 고정 임계값을 사용한다.

원칙: 패킷이 많다는 이유만으로 '공격'이라 단정하지 않는다.
각 규칙은 오탐 완화 조건(양방향 통신, 연결 성공률, 일반 서비스 포트)을 함께 본다.
반환하는 것은 '이상 징후 후보'이며, 중복 억제/저장은 engine 이 담당한다.
"""
from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from netcare.analysis import terms
from netcare.config import DetectionConfig

_QTYPES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 65: "HTTPS", 64: "SVCB", 12: "PTR"}

SEVERITY_ORDER = {"info": 0, "warning": 1, "danger": 2}
SEVERITY_KO = {"info": "정보", "warning": "주의", "danger": "위험"}


def grade(measured: float, threshold: float) -> str:
    ratio = measured / threshold if threshold else 0
    if ratio >= 3:
        return "danger"
    if ratio >= 1:
        return "warning"
    return "info"


def downgrade(sev: str) -> str:
    return {"danger": "warning", "warning": "info", "info": "info"}[sev]


@dataclass
class Bucket:
    src_pkts: Counter = field(default_factory=Counter)
    src_bytes: Counter = field(default_factory=Counter)
    pair_pkts: Counter = field(default_factory=Counter)        # (src, dst) 패킷 수
    syn: Counter = field(default_factory=Counter)              # src → 순수 SYN
    synack_to: Counter = field(default_factory=Counter)        # 연결을 시작한 쪽(dst) → 받은 SYN-ACK
    completed: Counter = field(default_factory=Counter)        # src → 3-way handshake 를 끝까지 완료한 횟수
    completed_target: Counter = field(default_factory=Counter) # (src, dst, dport) → 완료 횟수
    syn_to_dst: Counter = field(default_factory=Counter)       # dst → 받은 SYN (분산 출발지 대비)
    syn_srcs_to_dst: dict = field(default_factory=lambda: defaultdict(set))
    rst_to: Counter = field(default_factory=Counter)           # dst → 받은 RST
    syn_target: Counter = field(default_factory=Counter)       # (src, dst, dport) → SYN
    targets: dict = field(default_factory=lambda: defaultdict(set))  # src → {(dst, dport)} (SYN/UDP)
    port_pkts: Counter = field(default_factory=Counter)        # "TCP/443" → 패킷
    packets: int = 0
    bytes: int = 0
    dns_queries: int = 0
    dns_errors: int = 0
    dns_error_names: Counter = field(default_factory=Counter)
    dns_servers: Counter = field(default_factory=Counter)
    dns_unanswered: int = 0
    dns_partial: int = 0          # 같은 도메인의 다른 질의(A/AAAA)는 성공 → 사용자 영향 없음
    dns_partial_names: Counter = field(default_factory=Counter)


@dataclass
class Ewma:
    alpha: float = 0.05
    mean: float = 0.0
    var: float = 0.0
    n: int = 0

    def update(self, x: float):
        if self.n == 0:
            self.mean, self.var = x, 0.0
        else:
            d = x - self.mean
            self.mean += self.alpha * d
            self.var = (1 - self.alpha) * (self.var + self.alpha * d * d)
        self.n += 1

    @property
    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))


class Detector:
    MAX_TARGETS = 2000

    def __init__(self, cfg: DetectionConfig, local_ips: set[str] | None = None, local_macs: set[str] | None = None,
                 gateway_ip: str | None = None):
        self.cfg = cfg
        self.local_ips = local_ips or set()
        self.local_macs = local_macs or set()
        self.gateway_ip = gateway_ip
        self.local_nets: list = []       # ipaddress 네트워크 목록 (ARP·LAN 판단 범위)
        from netcare.detection.advanced import AdvancedDetector
        self.adv = AdvancedDetector(self)   # 확장 규칙 (스푸핑 의심 · 연결 품질)
        from netcare.detection.integrity import IntegrityDetector
        self.integ = IntegrityDetector(self)  # 패킷 무결성 (체크섬 · TCP 주입 · UDP 재전송)
        from netcare.detection.crowdsec_compat import CompatDetector
        self.compat = CompatDetector(self)    # CrowdSec 동등 시나리오
        self._lock = threading.Lock()
        self.buckets: dict[int, Bucket] = {}
        self.pending_dns: dict[tuple, tuple] = {}   # (id, client, server) → (질의 시각, 도메인, 질의 종류)
        self.dns_ok: dict[str, float] = {}          # 도메인 → 마지막 성공 응답 시각
        self.half_open: dict[tuple, float] = {}     # (src, sport, dst, dport) → SYN 시각 (핸드셰이크 미완료)
        self.bytes_baseline = Ewma()
        self.pps_baseline = Ewma()
        self.first_eval: float | None = None
        self.last_evaluated_sec: int | None = None
        self._whitelist_nets = []
        self.set_config(cfg)

    def set_config(self, cfg: DetectionConfig):
        self.cfg = cfg
        nets = []
        for w in cfg.whitelist:
            try:
                nets.append(ipaddress.ip_network(w, strict=False))
            except ValueError:
                pass
        self._whitelist_nets = nets

    def whitelisted(self, ip: str | None) -> bool:
        if not ip or not self._whitelist_nets:
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self._whitelist_nets)

    # ──────────────── 관측 ────────────────
    def observe(self, r: dict):
        sec = int(r["ts"] or time.time())
        with self._lock:
            b = self.buckets.get(sec)
            if b is None:
                b = self.buckets[sec] = Bucket()
            src, dst, size = r["src"], r["dst"], r["length"]
            b.packets += 1
            b.bytes += size
            if src:
                b.src_pkts[src] += 1
                b.src_bytes[src] += size
                if dst:
                    b.pair_pkts[(src, dst)] += 1
            if r["proto"] in ("TCP", "UDP") and r.get("service_port") is not None:
                b.port_pkts[f"{r['proto']}/{r['service_port']}"] += 1
            if r["proto"] == "TCP":
                fl = r.get("flags") or ""
                flow = (src, r["sport"], dst, r["dport"])
                if "S" in fl and "A" not in fl:
                    b.syn[src] += 1
                    b.syn_target[(src, dst, r["dport"])] += 1
                    b.syn_to_dst[dst] += 1
                    if len(b.syn_srcs_to_dst[dst]) < self.MAX_TARGETS:
                        b.syn_srcs_to_dst[dst].add(src)
                    if len(b.targets[src]) < self.MAX_TARGETS:
                        b.targets[src].add((dst, r["dport"]))
                    if len(self.half_open) < 50000:
                        self.half_open[flow] = r["ts"]
                elif "S" in fl and "A" in fl:
                    b.synack_to[dst] += 1
                elif "R" in fl:
                    b.rst_to[dst] += 1
                elif "A" in fl and self.half_open.pop(flow, None) is not None:
                    # 연결을 시작한 쪽이 SYN-ACK 에 ACK 로 답함 → 핸드셰이크 완료
                    b.completed[src] += 1
                    b.completed_target[(src, dst, r["dport"])] += 1
            elif r["proto"] == "UDP" and r.get("dns_qname") is None and src and \
                    not (terms.SERVICES.get(("UDP", r["sport"])) or terms.SERVICES.get((None, r["sport"]))):
                # 서비스 포트에서 오는 '응답'은 제외하고, 들어오는 UDP 스캔도 집계
                if len(b.targets[src]) < self.MAX_TARGETS:
                    b.targets[src].add((dst, r["dport"]))
            # mDNS(5353)·LLMNR(5355)·멀티캐스트 DNS 는 1:1 응답이 오지 않으므로 무응답 판정에서 제외
            mdns = r.get("sport") in (5353, 5355) or r.get("dport") in (5353, 5355) or \
                (dst or "").startswith(("224.", "ff0", "FF0"))
            if r.get("dns_id") is not None and not mdns:
                if r.get("dns_qr") == 0:
                    b.dns_queries += 1
                    if len(self.pending_dns) < 20000:
                        self.pending_dns[(r["dns_id"], src, dst)] = (r["ts"], r.get("dns_qname"), r.get("dns_qtype"))
                else:
                    self.pending_dns.pop((r["dns_id"], dst, src), None)
                    if r.get("dns_rcode") == 0 and r.get("dns_qname") and len(self.dns_ok) < 50000:
                        self.dns_ok[r["dns_qname"]] = r["ts"]
                    qn = (r.get("dns_qname") or "").lower()
                    # 서비스 탐색(DNS-SD)·역방향 조회(PTR)는 '없음(NXDOMAIN)'이 정상 응답이라 실패로 세지 않는다 (실측 오탐 사례)
                    benign_nx = r.get("dns_rcode") == 3 and ("_dns-sd._udp" in qn or qn.endswith((".in-addr.arpa", ".ip6.arpa")))
                    if r.get("dns_rcode") not in (0, None) and not benign_nx:
                        b.dns_errors += 1
                        b.dns_servers[src] += 1
                        if r.get("dns_qname"):
                            b.dns_error_names[r["dns_qname"]] += 1
        try:
            self.adv.observe(r)
        except Exception:  # 확장 규칙 오류가 기존 탐지를 막지 않도록
            pass
        try:
            self.integ.observe(r)
        except Exception:
            pass
        if self.cfg.crowdsec_compat:
            try:
                self.compat.observe(r)
            except Exception:
                pass

    # ──────────────── 평가 ────────────────
    def _window(self, now: float) -> list[Bucket]:
        end = int(now)
        return [self.buckets[s] for s in range(end - self.cfg.window_sec, end) if s in self.buckets]

    def evaluate(self, now: float | None = None) -> list[dict]:
        now = now if now is not None else time.time()
        cfg = self.cfg
        W = cfg.window_sec
        out: list[dict] = []
        with self._lock:
            # 오래된 버킷 정리
            cutoff = int(now) - max(W, 10) - 5
            for k in [k for k in self.buckets if k < cutoff]:
                del self.buckets[k]
            # 오래된 미완료 핸드셰이크 정리
            if len(self.half_open) > 10000:
                lim = now - W * 2
                self.half_open = {k: t for k, t in self.half_open.items() if t >= lim}
            # 3초 넘게 응답 없는 DNS 질의 → 무응답 처리
            sec = int(now) - 1
            stale = [k for k, v in self.pending_dns.items() if now - v[0] > 3]
            if stale:
                tb = self.buckets.setdefault(sec, Bucket())
                for k in stale:
                    t, qname, qtype = self.pending_dns.pop(k)
                    if qname and self.dns_ok.get(qname, 0) >= t - 5:
                        # 예: AAAA(IPv6) 질의만 무응답이고 A(IPv4) 질의는 성공 → 사이트 접속에는 문제 없음
                        tb.dns_partial += 1
                        tb.dns_partial_names[f"{qname} ({_QTYPES.get(qtype, qtype)})"] += 1
                    else:
                        tb.dns_unanswered += 1
                        tb.dns_servers[k[2]] += 1
                        if qname:
                            tb.dns_error_names[qname] += 1
            if len(self.dns_ok) > 20000:
                lim = now - 60
                self.dns_ok = {k: v for k, v in self.dns_ok.items() if v >= lim}

            win = self._window(now)
            if self.first_eval is None:
                self.first_eval = now
            if not win:
                return out
            src_pkts, src_bytes, pair, syn, synack, rst, syn_target, port_pkts = (Counter() for _ in range(8))
            completed, syn_to_dst, completed_target = Counter(), Counter(), Counter()
            syn_srcs: dict[str, set] = defaultdict(set)
            targets: dict[str, set] = defaultdict(set)
            total_pkts = total_bytes = dns_q = dns_err = dns_unans = dns_part = 0
            dns_names, dns_servers, dns_part_names = Counter(), Counter(), Counter()
            for b in win:
                src_pkts.update(b.src_pkts); src_bytes.update(b.src_bytes); pair.update(b.pair_pkts)
                syn.update(b.syn); synack.update(b.synack_to); rst.update(b.rst_to)
                syn_target.update(b.syn_target); port_pkts.update(b.port_pkts)
                completed.update(b.completed); syn_to_dst.update(b.syn_to_dst); completed_target.update(b.completed_target)
                for d, ss in b.syn_srcs_to_dst.items():
                    if len(syn_srcs[d]) < self.MAX_TARGETS:
                        syn_srcs[d] |= ss
                for s, t in b.targets.items():
                    if len(targets[s]) < self.MAX_TARGETS:
                        targets[s] |= t
                total_pkts += b.packets; total_bytes += b.bytes
                dns_q += b.dns_queries; dns_err += b.dns_errors; dns_unans += b.dns_unanswered
                dns_part += b.dns_partial; dns_part_names.update(b.dns_partial_names)
                dns_names.update(b.dns_error_names); dns_servers.update(b.dns_servers)

            # 직전 1초 값으로 기준선 갱신 (이상 구간은 학습에서 제외)
            last = self.buckets.get(int(now) - 1)
            last_bytes = last.bytes if last else 0
            last_pkts = last.packets if last else 0

            out += self._rule_ip_flood(src_pkts, pair, W)
            out += self._rule_syn(syn, synack, rst, completed, syn_to_dst, syn_srcs, W)
            out += self._rule_port_concentration(port_pkts, total_pkts, W)
            surge = self._rule_traffic_surge(win, now, W)
            out += surge
            out += self._rule_repeat(syn_target, synack, rst, W, completed_target)
            out += self._rule_scan(targets, W)
            out += self._rule_peer(src_bytes, total_bytes, pair, W)
            out += self._rule_dns(dns_q, dns_err, dns_unans, dns_names, dns_servers, W, dns_part, dns_part_names)
            try:
                out += self.adv.evaluate(now, W)
            except Exception:
                pass
            try:
                out += self.integ.evaluate(now, W)
            except Exception:
                pass
            if self.cfg.crowdsec_compat:
                try:
                    comp = self.compat.evaluate(now, W)
                    # 같은 출발지의 포트 스캔을 기본 규칙도 잡았으면 하나로 합친다 (근거가 더 풍부한 기본 규칙 유지)
                    scans = {a.get("src"): a for a in out if a["type"] == "port_scan"}
                    for c in comp:
                        base = scans.get(c.get("src")) if c["type"] == "port_scan" else None
                        if base is not None:
                            base["evidence"]["crowdsec"] = c["evidence"]["crowdsec"]
                        else:
                            out.append(c)
                except Exception:
                    pass

            if self.last_evaluated_sec != int(now) - 1:
                self.last_evaluated_sec = int(now) - 1
                if not surge:
                    self.bytes_baseline.update(last_bytes)
                    self.pps_baseline.update(last_pkts)
        for a in out:
            a.setdefault("detected_at", now)
        return [a for a in out if not (self.whitelisted(a.get("src")) or self.whitelisted(a.get("dst")))]

    # 각 규칙 ------------------------------------------------------------
    def _rule_ip_flood(self, src_pkts: Counter, pair: Counter, W: int) -> list[dict]:
        th = self.cfg.ip_pps_threshold
        res = []
        for ip, n in src_pkts.most_common(5):
            pps = n / W
            if pps < th:
                break
            # 오탐 완화: 상대가 반대 방향으로도 통신하면(응답/ACK) 정상 대용량 전송 가능성
            peers = [(d, c) for (s, d), c in pair.items() if s == ip]
            top_peer, top_cnt = max(peers, key=lambda x: x[1]) if peers else (None, 0)
            reverse = pair.get((top_peer, ip), 0) if top_peer else 0
            reverse_ratio = reverse / top_cnt if top_cnt else 0
            sev = grade(pps, th)
            # TCP 수신 측은 지연 ACK·수신 병합 때문에 데이터 5~10개당 ACK 1개 정도만 보낸다 (실측 0.19).
            # 일방적인 폭주는 응답이 거의 0 이므로 5% 이상이면 양방향(정상 전송 가능성)으로 본다.
            bidirectional = reverse_ratio >= 0.05
            if bidirectional:
                sev = "info" if ip in self.local_ips else downgrade(sev)
            res.append(dict(type="ip_packet_flood", severity=sev, src=ip, dst=top_peer, port=None, protocol=None,
                            criterion=f"{W}초 평균 초당 패킷 {th:g}개 이상", threshold=th, measured=round(pps, 1),
                            evidence={"window_sec": W, "packets": n, "pps": round(pps, 1), "top_peer": top_peer,
                                      "reverse_packets": reverse, "reverse_ratio": round(reverse_ratio, 2),
                                      "bidirectional": bidirectional}))
        return res

    def _rule_syn(self, syn: Counter, synack: Counter, rst: Counter, completed: Counter, syn_to_dst: Counter,
                  syn_srcs: dict, W: int) -> list[dict]:
        """SYN 급증. '연결 성공'은 시작한 쪽이 마지막 ACK 까지 보내 3-way handshake 를 완료한 경우로 본다.

        (SYN Flood 에서는 피해 서버가 SYN-ACK 를 보내지만 공격자가 마지막 ACK 를 보내지 않는다.)
        """
        th = self.cfg.syn_threshold
        limit = self.cfg.syn_success_ratio_max
        res = []
        for ip, n in syn.most_common(5):
            if n < th:
                break
            done = completed.get(ip, 0)
            success = done / n if n else 0
            if success >= limit and n < th * 3:
                continue  # 대부분 연결이 성공 → 정상적인 연결 폭주(브라우저 등)로 보고 알리지 않음
            sev = "info" if success >= limit else grade(n, th)
            res.append(dict(type="syn_surge", severity=sev, src=ip, dst=None, port=None, protocol="TCP",
                            criterion=f"{W}초 동안 새 연결 요청(SYN) {th}개 이상 & 연결 완료율 {limit:.0%} 미만",
                            threshold=th, measured=n,
                            evidence={"window_sec": W, "syn": n, "completed": done, "success_ratio": round(success, 2),
                                      "syn_ack": synack.get(ip, 0), "rst_received": rst.get(ip, 0), "distributed": False}))
        # 출발지를 여러 개로 나눈(분산/위조) SYN 이 한 대상에 몰리는 경우
        flagged = {r["src"] for r in res}
        for dst, n in syn_to_dst.most_common(3):
            if n < th * 2:
                break
            srcs = syn_srcs.get(dst, set())
            if len(srcs) < 10 or srcs <= flagged:
                continue
            done = sum(completed.get(s, 0) for s in srcs)
            success = done / n
            if success >= limit:
                continue
            res.append(dict(type="syn_surge", severity=grade(n, th * 2), src=None, dst=dst, port=None, protocol="TCP",
                            criterion=f"{W}초 동안 한 장치로 SYN {th * 2}개 이상(여러 출발지) & 연결 완료율 {limit:.0%} 미만",
                            threshold=th * 2, measured=n,
                            evidence={"window_sec": W, "syn": n, "completed": done, "success_ratio": round(success, 2),
                                      "distinct_sources": len(srcs), "distributed": True, "syn_ack": 0, "rst_received": 0}))
        return res

    def _rule_port_concentration(self, port_pkts: Counter, total: int, W: int) -> list[dict]:
        if total < self.cfg.port_min_packets or not port_pkts:
            return []
        key, n = port_pkts.most_common(1)[0]
        share = n / total
        th = self.cfg.port_share_threshold
        if share < th:
            return []
        proto, port = key.split("/")
        port = int(port)
        common = port in terms.COMMON_BULK_PORTS
        sev = "info" if common else ("danger" if total >= self.cfg.port_min_packets * 3 else "warning")
        return [dict(type="port_concentration", severity=sev, src=None, dst=None, port=port, protocol=proto,
                     criterion=f"{W}초 동안 한 포트가 전체의 {th:.0%} 이상 & 패킷 {self.cfg.port_min_packets}개 이상",
                     threshold=th, measured=round(share, 3),
                     evidence={"window_sec": W, "port_packets": n, "total_packets": total, "share": round(share, 3),
                               "common_service": common, "service": terms.service_for(proto, port, port)[0]})]

    def _rule_traffic_surge(self, win: list[Bucket], now: float, W: int) -> list[dict]:
        # 최근 5초 평균으로 판단 (순간 튐 완화)
        recent = [self.buckets.get(s) for s in range(int(now) - 5, int(now))]
        bps = sum(b.bytes for b in recent if b) / 5
        warm = (self.bytes_baseline.n >= self.cfg.warmup_sec)
        base = self.bytes_baseline
        if warm:
            std = max(base.std, base.mean * 0.1, 1.0)  # 표준편차가 0에 가까울 때 과민 반응 방지
            z = (bps - base.mean) / std
            if z < self.cfg.traffic_z_threshold or bps < self.cfg.traffic_min_bps:
                return []
            # 사용량 급증은 '위협'이 아니라 사용 패턴 변화 신호이므로 최대 '주의'로 표시한다
            sev = "warning"
            return [dict(type="traffic_surge", severity=sev, src=None, dst=None, port=None, protocol=None,
                         criterion=f"평소 기준선 대비 z-score {self.cfg.traffic_z_threshold:g} 이상 & {terms.human_rate(self.cfg.traffic_min_bps)} 이상",
                         threshold=round(base.mean + self.cfg.traffic_z_threshold * std, 1), measured=round(bps, 1),
                         evidence={"method": "EWMA z-score", "baseline_mean_bps": round(base.mean, 1), "baseline_std": round(std, 1),
                                   "z_score": round(z, 2), "current_bps": round(bps, 1), "learned_seconds": base.n})]
        th = self.cfg.traffic_static_bps
        if bps < th:
            return []
        return [dict(type="traffic_surge", severity="warning", src=None, dst=None, port=None, protocol=None,
                     criterion=f"기준선 학습 전 고정 임계값 {terms.human_rate(th)} 이상",
                     threshold=th, measured=round(bps, 1),
                     evidence={"method": "고정 임계값(학습 중)", "current_bps": round(bps, 1), "learned_seconds": base.n,
                               "warmup_sec": self.cfg.warmup_sec})]

    def _rule_repeat(self, syn_target: Counter, synack: Counter, rst: Counter, W: int,
                     completed_target: Counter | None = None) -> list[dict]:
        """같은 목적지·포트로 반복 연결. 연결이 대부분 성공하면(폴링·API 호출 등) 정상 사용으로 본다."""
        th = self.cfg.repeat_conn_threshold
        completed_target = completed_target or Counter()
        res = []
        for key, n in syn_target.most_common(5):
            if n < th:
                break
            src, dst, dport = key
            done = completed_target.get(key, 0)
            success = done / n
            if success >= 0.5 and n < th * 3:
                continue
            sev = "info" if success >= 0.5 else grade(n, th)
            res.append(dict(type="repeated_connection", severity=sev, src=src, dst=dst, port=dport, protocol="TCP",
                            criterion=f"{W}초 동안 같은 목적지·포트로 연결 요청 {th}회 이상 (연결 완료율 50% 미만)",
                            threshold=th, measured=n,
                            evidence={"window_sec": W, "attempts": n, "completed": done, "success_ratio": round(success, 2),
                                      "rst_received": rst.get(src, 0), "syn_ack_received": synack.get(src, 0)}))
        return res

    def _rule_scan(self, targets: dict, W: int) -> list[dict]:
        th = self.cfg.port_scan_threshold
        res = []
        for src, t in sorted(targets.items(), key=lambda kv: -len(kv[1]))[:5]:
            n = len(t)
            if n < th:
                break
            dsts = {d for d, _ in t}
            ports = {p for _, p in t}
            pattern = "한 장치의 여러 포트" if len(dsts) == 1 else ("여러 장치의 같은 포트" if len(ports) <= 3 else "여러 장치·여러 포트")
            res.append(dict(type="port_scan", severity=grade(n, th), src=src, dst=next(iter(dsts)) if len(dsts) == 1 else None,
                            port=next(iter(ports)) if len(ports) == 1 else None, protocol=None,
                            criterion=f"{W}초 동안 서로 다른 목적지·포트 {th}곳 이상에 연결 시도",
                            threshold=th, measured=n,
                            evidence={"window_sec": W, "distinct_targets": n, "distinct_hosts": len(dsts),
                                      "distinct_ports": len(ports), "pattern": pattern,
                                      "sample_ports": sorted(p for p in ports if p is not None)[:15]}))
        return res

    def _rule_peer(self, src_bytes: Counter, total_bytes: int, pair: Counter, W: int) -> list[dict]:
        if total_bytes <= 0 or not src_bytes:
            return []
        ip, b = src_bytes.most_common(1)[0]
        share = b / total_bytes
        rate = b / W
        if share < self.cfg.peer_share_threshold or rate < self.cfg.peer_min_bps:
            return []
        if ip in self.local_ips:
            return []  # 내 컴퓨터가 보내는 대용량은 트래픽 급증 규칙에서 다룸
        fwd = sum(c for (s, _d), c in pair.items() if s == ip)
        rev = sum(c for (_s, d), c in pair.items() if d == ip)
        bidirectional = fwd > 0 and rev / fwd >= 0.05
        sev = "warning" if rate >= self.cfg.peer_min_bps * 3 and not bidirectional else "info"
        return [dict(type="heavy_peer", severity=sev, src=ip, dst=None, port=None, protocol=None,
                     criterion=f"한 장치가 전체 데이터의 {self.cfg.peer_share_threshold:.0%} 이상 & {terms.human_rate(self.cfg.peer_min_bps)} 이상",
                     threshold=self.cfg.peer_share_threshold, measured=round(share, 3),
                     evidence={"window_sec": W, "bytes": b, "share": round(share, 3), "rate_bps": round(rate, 1),
                               "bidirectional": bidirectional, "reverse_packets": rev})]

    def _rule_dns(self, q: int, err: int, unans: int, names: Counter, servers: Counter, W: int,
                  partial: int = 0, partial_names: Counter | None = None) -> list[dict]:
        """DNS 실패. 같은 도메인의 다른 질의가 성공한 무응답(partial)은 실패로 세지 않는다."""
        fails = err + unans
        th = self.cfg.dns_failure_threshold
        if fails < th:
            return []
        ratio = fails / max(q - partial, fails)
        if ratio < self.cfg.dns_failure_ratio:
            return []
        server = servers.most_common(1)[0][0] if servers else None
        return [dict(type="dns_failure", severity=grade(fails, th), src=server, dst=None, port=53, protocol="UDP",
                     criterion=f"{W}초 동안 DNS 실패(오류+무응답) {th}건 이상 & 실패율 {self.cfg.dns_failure_ratio:.0%} 이상",
                     threshold=th, measured=fails,
                     evidence={"window_sec": W, "queries": q, "error_responses": err, "unanswered": unans,
                               "failure_ratio": round(ratio, 2), "failed_names": [n for n, _ in names.most_common(5)],
                               "dns_server": server, "partial_unanswered": partial,
                               "partial_names": [n for n, _ in (partial_names or Counter()).most_common(5)]})]

    def baseline_info(self) -> dict:
        b = self.bytes_baseline
        return {"learned_seconds": b.n, "warmup_sec": self.cfg.warmup_sec, "warm": b.n >= self.cfg.warmup_sec,
                "mean_bps": round(b.mean, 1), "std_bps": round(b.std, 1), "mean_pps": round(self.pps_baseline.mean, 1)}


def probe_anomalies(probe: dict, cfg_probe) -> list[dict]:
    """Prober 실측 결과 → 연결 품질 이상 징후."""
    out = []
    now = time.time()
    gw = probe.get("gateway") or {}
    ext = probe.get("external") or {}
    dns = probe.get("dns") or {}
    if gw.get("target") and gw.get("sent"):
        loss = gw.get("loss_pct", 0)
        if loss >= cfg_probe.gateway_loss_warn:
            out.append(dict(type="gateway_unreachable" if loss >= 100 else "packet_loss",
                            severity="danger" if loss >= 100 else "warning",
                            src=None, dst=gw["target"], port=None, protocol="ICMP",
                            criterion=f"공유기(게이트웨이) ping 손실률 {cfg_probe.gateway_loss_warn:g}% 이상",
                            threshold=cfg_probe.gateway_loss_warn, measured=loss, detected_at=now,
                            evidence={"target": gw["target"], "sent": gw.get("sent"), "received": gw.get("received"),
                                      "loss_pct": loss, "avg_ms": gw.get("avg_ms")}))
        elif gw.get("avg_ms") and gw["avg_ms"] >= cfg_probe.latency_warn_ms:
            out.append(dict(type="high_latency", severity="warning", src=None, dst=gw["target"], port=None, protocol="ICMP",
                            criterion=f"공유기 응답 시간 {cfg_probe.latency_warn_ms:g}ms 이상",
                            threshold=cfg_probe.latency_warn_ms, measured=gw["avg_ms"], detected_at=now,
                            evidence={"target": gw["target"], "avg_ms": gw["avg_ms"], "max_ms": gw.get("max_ms")}))
    if ext.get("target") and ext.get("sent") and not out:
        loss = ext.get("loss_pct", 0)
        if loss >= cfg_probe.gateway_loss_warn:
            out.append(dict(type="packet_loss", severity="warning", src=None, dst=ext["target"], port=None, protocol="ICMP",
                            criterion=f"외부 인터넷 ping 손실률 {cfg_probe.gateway_loss_warn:g}% 이상",
                            threshold=cfg_probe.gateway_loss_warn, measured=loss, detected_at=now,
                            evidence={"target": ext["target"], "sent": ext.get("sent"), "received": ext.get("received"),
                                      "loss_pct": loss, "avg_ms": ext.get("avg_ms"), "gateway_ok": bool(gw.get("received"))}))
        elif ext.get("avg_ms") and ext["avg_ms"] >= cfg_probe.latency_warn_ms:
            out.append(dict(type="high_latency", severity="info", src=None, dst=ext["target"], port=None, protocol="ICMP",
                            criterion=f"외부 인터넷 응답 시간 {cfg_probe.latency_warn_ms:g}ms 이상",
                            threshold=cfg_probe.latency_warn_ms, measured=ext["avg_ms"], detected_at=now,
                            evidence={"target": ext["target"], "avg_ms": ext["avg_ms"]}))
    if dns.get("tested") and dns.get("failed", 0) == dns.get("tested"):
        out.append(dict(type="dns_failure", severity="danger", src=None, dst=None, port=53, protocol="UDP",
                        criterion="DNS 조회 테스트 전부 실패", threshold=1, measured=dns["failed"], detected_at=now,
                        evidence={"queries": dns["tested"], "error_responses": 0, "unanswered": dns["failed"],
                                  "failure_ratio": 1.0, "failed_names": [r["domain"] for r in dns.get("results", []) if not r.get("ok")],
                                  "source": "probe"}))
    return out
