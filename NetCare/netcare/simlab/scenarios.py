"""Simulation Lab 시나리오 12종 + 정상 기준선 — [합성 데이터] 생성기.

설계 원칙
- 같은 시나리오·조건·시드 → 항상 같은 패킷 (random.Random(seed) 하나만 사용)
- 매 초 step(s, effects) 를 호출해 그 초의 패킷을 만든다. 가상 대응 조치(Effects)가 바뀌면
  다음 초부터 생성 결과가 달라진다 → '조치 전후 비교' 가 가능
- 공격/장애 구간은 [attack_start, attack_end) 초. 이것이 평가의 정답(ground truth)이다
- 모든 패킷에 정답 라벨(benign / 시나리오 id)을 붙인다 (헤더에는 넣지 않음)
"""
from __future__ import annotations

import heapq
import random
import statistics
from dataclasses import dataclass, field

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from netcare.simlab import network as N

BENIGN = "benign"


@dataclass
class ScenarioSpec:
    id: str
    kind: str                      # attack | fault | baseline
    title: str
    desc: str
    icon: str
    expected: set                  # 이 구간에 나와야 하는 탐지 유형
    acceptable: set = field(default_factory=set)   # 관련 징후 (오탐으로 세지 않음)
    certainty_note: str = ""
    remedy: str | None = None      # 권장 가상 조치 (auto 정책에서 사용)
    metric: str = ""               # 조치 전후 비교 지표 이름
    metric_label: str = ""
    metric_better: str = "lower"


SCENARIOS: dict[str, ScenarioSpec] = {s.id: s for s in [
    ScenarioSpec("normal", "baseline", "정상 트래픽 (기준선)", "공격·장애 없이 웹·DNS·스트리밍·내부 서버 접속만 발생. 오탐(False Positive) 측정용", "🌿",
                 set(), metric="total", metric_label="초당 패킷"),
    ScenarioSpec("ip_spoof", "attack", "IP Spoofing", "출발지 주소를 조작한 패킷: 내 주소 도용, LAN 장치 사칭(MAC 불일치), 예약 주소, TTL 급변, 요청 없는 SYN-ACK", "🎭",
                 {"ip_spoof_suspect"}, {"syn_surge"}, "패킷만으로 위조를 확정할 수 없어 '의심'으로만 판정", "ingress_filter",
                 "spoofed", "LAN에 들어온 위조 패킷/초"),
    ScenarioSpec("arp_spoof", "attack", "ARP Spoofing", "공격자가 '공유기 IP = 내 MAC'이라는 위조 ARP 응답을 반복해 트래픽을 가로챔", "🪤",
                 {"arp_spoof"}, {"ip_spoof_suspect"}, "DHCP 재할당·장비 교체와 구분이 어려워 '의심'으로 표시", "static_arp",
                 "redirected", "공격자 MAC으로 간 내 프레임/초"),
    ScenarioSpec("dns_spoof", "attack", "DNS Spoofing", "공격자가 DNS 서버를 사칭해 진짜보다 먼저 가짜 IP 응답을 보냄(경합 위조)", "🧪",
                 {"dns_spoof_suspect"}, {"ip_spoof_suspect"}, "처음부터 위조 응답 하나만 오면 구분 불가 → '의심'", "trusted_dns",
                 "forged", "먼저 도착한 위조 DNS 응답/초"),
    ScenarioSpec("port_scan", "attack", "Port Scanning", "LAN의 공격자가 내 컴퓨터의 TCP·UDP 포트를 차례로 두드림", "🔍",
                 {"port_scan"}, {"syn_surge", "repeated_connection"}, "", "host_block", "exposed", "스캐너에게 보낸 응답/초"),
    ScenarioSpec("syn_flood", "attack", "SYN Flood", "외부 공격자가 응답(ACK)을 끝맺지 않는 연결 요청을 대량 전송", "🌊",
                 {"syn_surge"}, {"repeated_connection", "port_concentration", "ip_packet_flood"}, "", "host_block",
                 "halfopen", "공격자에게 보낸 SYN-ACK/초(자원 소모)"),
    ScenarioSpec("repeated", "attack", "반복 연결 요청", "같은 대상(내 컴퓨터 3389 원격 데스크톱, 닫힘)에 연결을 반복 시도", "🔂",
                 {"repeated_connection"}, {"syn_surge"}, "", "host_block", "refused", "공격자에게 보낸 거부(RST)/초"),
    ScenarioSpec("packet_loss", "fault", "Packet Loss", "내 접속 구간에서 데이터 일부가 사라짐 → 재전송·중복 ACK 증가", "📉",
                 {"tcp_loss"}, set(), "", "end_fault", "loss", "손실 이벤트/초"),
    ScenarioSpec("latency", "fault", "Latency", "모든 응답이 고정적으로 늦게 도착", "🐢",
                 {"latency_rise"}, set(), "", "end_fault", "rtt", "RTT 중앙값(ms)"),
    ScenarioSpec("jitter", "fault", "Jitter", "응답 지연이 매번 불규칙하게 변함", "〰️",
                 {"jitter_high"}, {"latency_rise"}, "", "end_fault", "jitter", "연속 RTT 차이(ms)"),
    ScenarioSpec("dns_failure", "fault", "DNS Failure", "DNS 서버가 오류(SERVFAIL)를 주거나 응답하지 않음", "🧭",
                 {"dns_failure"}, set(), "", "trusted_dns", "dnsfail", "실패한 주소 조회/초"),
    ScenarioSpec("bandwidth", "fault", "Bandwidth Limiting", "회선 속도가 일정 값으로 제한되고 대기열이 쌓여 지연 증가", "🚦",
                 {"bandwidth_limit_suspect"}, {"latency_rise", "jitter_high"}, "원래 느린 회선과 구분이 거의 불가능 → '의심' 수준",
                 "end_fault", "throughput", "스트리밍 처리량(KB/s)", "higher"),
    ScenarioSpec("conn_failure", "fault", "Connection Failure", "평소 쓰던 내부 서버(10.77.0.20:443)가 응답을 멈춤", "🔌",
                 {"connection_failure"}, set(), "", "end_fault", "connfail", "실패한 연결 시도/초"),
]}

DEFAULTS = {"intensity": 1.0, "duration": 40, "attack_start": 12, "attack_end": 32, "seed": 7, "background": True}


def normalize_params(scenario_id: str, params: dict | None) -> dict:
    if scenario_id not in SCENARIOS:
        raise ValueError(f"알 수 없는 시나리오예요: {scenario_id}")
    p = dict(DEFAULTS)
    for k, v in (params or {}).items():
        if k in DEFAULTS and v not in (None, ""):
            p[k] = type(DEFAULTS[k])(v) if not isinstance(DEFAULTS[k], bool) else bool(v)
    p["intensity"] = min(max(p["intensity"], 0.05), 5.0)
    p["duration"] = min(max(p["duration"], 15), 180)
    p["attack_start"] = min(max(p["attack_start"], 0), p["duration"] - 1)
    p["attack_end"] = min(max(p["attack_end"], p["attack_start"] + 1), p["duration"])
    if SCENARIOS[scenario_id].kind == "fault":
        p["background"] = True   # 장애는 정상 통신에 영향을 주는 것이므로 배경 트래픽이 필요
    return p


class LabGenerator:
    def __init__(self, scenario_id: str, params: dict):
        self.spec = SCENARIOS[scenario_id]
        self.p = normalize_params(scenario_id, params)
        self.rng = random.Random(self.p["seed"])
        self.i = self.p["intensity"]
        self._heap: list = []
        self._n = 0
        self.metrics: dict[int, dict] = {}
        self.stream_seq = 1_000_000
        self.stream_port = 50500
        self.scan_port = 1
        self.gw_mac_cache = N.GW_MAC      # 내 컴퓨터의 ARP 캐시에 있는 '공유기 MAC'
        self.packets_total = 0
        self.packets_attack = 0

    # ── 내부 도우미 ──
    def _emit(self, t: float, pkt, label: str = BENIGN):
        heapq.heappush(self._heap, (t, self._n, pkt, label))
        self._n += 1

    def active(self, s: int) -> bool:
        return self.p["attack_start"] <= s < self.p["attack_end"]

    def _fault_on(self, s: int, effects: N.Effects, kind: str) -> bool:
        return self.spec.id == kind and self.active(s) and not effects.fault_cleared

    def _delay(self, s: int, effects: N.Effects) -> float:
        """응답에 더해지는 지연(초)."""
        d = 0.0
        if self._fault_on(s, effects, "latency"):
            d += 0.150 * self.i
        if self._fault_on(s, effects, "jitter"):
            d += self.rng.uniform(0, 0.250 * self.i)
        if self._fault_on(s, effects, "bandwidth"):
            d += 0.200 * self.i + self.rng.uniform(0, 0.01)   # 대기열 적체
        return d

    def _loss_p(self, s: int, effects: N.Effects) -> float:
        return 0.08 * self.i if self._fault_on(s, effects, "packet_loss") else 0.0

    def _ext_mac(self) -> str:
        return self.gw_mac_cache

    # ── 1초 생성 ──
    def step(self, s: int, effects: N.Effects) -> list[tuple[float, object, str]]:
        m = {"total": 0, "attack": 0, "spoofed": 0, "redirected": 0, "forged": 0, "exposed": 0, "halfopen": 0, "refused": 0,
             "loss": 0, "dnsfail": 0, "connfail": 0, "throughput": 0.0, "rtts": []}
        self._m = m
        if effects.static_arp:
            self.gw_mac_cache = N.GW_MAC      # 공유기 MAC 고정 → 오염된 캐시 복구
        if self.p["background"] or self.spec.kind == "baseline":
            self._background(s, effects)
        if self.active(s):
            fn = getattr(self, f"_atk_{self.spec.id}", None)
            if fn:
                fn(s, effects)
        out = []
        while self._heap and self._heap[0][0] < s + 1:
            t, _, pkt, label = heapq.heappop(self._heap)
            out.append((t, pkt, label))
            m["total"] += 1
            if label != BENIGN:
                m["attack"] += 1
        m["redirected"] = self.count_redirected(out)
        self.packets_total += m["total"]
        self.packets_attack += m["attack"]
        rtts = m.pop("rtts")
        m["rtt"] = round(statistics.median(rtts), 1) if rtts else None
        m["jitter"] = round(statistics.fmean(abs(rtts[k] - rtts[k - 1]) for k in range(1, len(rtts))), 1) if len(rtts) > 2 else None
        m["throughput"] = round(m["throughput"] / 1000, 1)
        m["effects"] = {"host_blocked": sorted(effects.host_blocked), "static_arp": effects.static_arp, "trusted_dns": effects.trusted_dns,
                        "ingress_filter": effects.ingress_filter, "fault_cleared": effects.fault_cleared}
        self.metrics[s] = m
        return out

    def drain(self) -> list:
        out = []
        while self._heap:
            t, _, pkt, label = heapq.heappop(self._heap)
            out.append((t, pkt, label))
        return out

    # ── 정상 배경 트래픽 ──
    def _background(self, s: int, e: N.Effects):
        r, m = self.rng, self._m
        # ARP: 5초마다 공유기, DNS 서버 주소 확인 (정상 응답)
        if s % 5 == 0:
            self._emit(s + 0.001, N.arp_request(N.GW_IP))
            self._emit(s + 0.002, N.arp_reply(N.GW_IP, N.GW_MAC))
            if not (self.spec.id == "arp_spoof" and self.active(s) and not e.static_arp and self.gw_mac_cache != N.GW_MAC):
                self.gw_mac_cache = N.GW_MAC
        if s % 5 == 2:
            self._emit(s + 0.003, N.arp_request(N.DNS_IP))
            self._emit(s + 0.004, N.arp_reply(N.DNS_IP, N.DNS_MAC))
        # ping 공유기 (2초마다)
        if s % 2 == 0:
            t = s + 0.05
            self._emit(t, N.from_client(N.GW_IP, ICMP(type=8, id=7, seq=s)))
            if r.random() >= self._loss_p(s, e):
                self._emit(t + 0.002 + self._delay(s, e), N.to_client(N.GW_IP, ICMP(type=0, id=7, seq=s), ttl=64))
            else:
                m["loss"] += 1
        self._stream(s, e)
        for _ in range(2):
            self._dns_lookup(s, e)
        for _ in range(2):
            self._web_session(s, e, r.choice(list(N.SITES)))
        self._intranet(s, e)

    def _stream(self, s, e):
        """동영상 스트리밍처럼 계속 이어지는 다운로드 흐름."""
        r, m = self.rng, self._m
        if self._fault_on(s, e, "bandwidth"):
            target = 45_000 * (1 + r.uniform(-0.02, 0.02))          # 일정하게 막힌 처리량
        else:
            target = r.uniform(60_000, 140_000)                     # 평소에는 들쭉날쭉
        n = max(1, int(target / 1400))
        p = self._loss_p(s, e)
        srv, sp, dp = N.STREAM_SERVER, 443, self.stream_port
        for k in range(n):
            t = s + (k + r.random() * 0.5) / n
            seq = self.stream_seq
            seg = N.to_client(srv, TCP(sport=sp, dport=dp, flags="A", seq=seq, ack=1, window=501) / N.tls_data(1400))
            self.stream_seq += 1400
            if r.random() < p:
                # 들어오는 데이터 손실: 원본은 도착하지 않고, 내 컴퓨터가 같은 ACK 를 반복(3중 중복 ACK) → 재전송 도착
                for d in range(4):
                    self._emit(t + 0.0005 * (d + 1), N.from_client(srv, TCP(sport=dp, dport=sp, flags="A", seq=1, ack=seq, window=2048),
                                                                  dst_mac=self._ext_mac()))
                self._emit(t + 0.2 + self._delay(s, e), seg)
                m["loss"] += 1
            else:
                self._emit(t, seg)
                m["throughput"] += len(seg)
            if k % 2 == 1:
                self._emit(t + 0.0003, N.from_client(srv, TCP(sport=dp, dport=sp, flags="A", seq=1, ack=self.stream_seq, window=2048),
                                                     dst_mac=self._ext_mac()))

    def _dns_lookup(self, s, e, extra: bool = False):
        r, m = self.rng, self._m
        if not extra and r.random() < 0.3:
            return
        ip = r.choice(list(N.SITES))
        name = N.SITES[ip][0]
        t = s + r.uniform(0, 0.9)
        if e.trusted_dns:
            # 암호화 DNS(DoT, TCP 853): 내용이 암호화돼 끼어들 수 없음
            sp = r.randint(40000, 60000)
            self._emit(t, N.from_client(N.DOT_IP, TCP(sport=sp, dport=853, flags="PA", seq=1, ack=1) / N.tls_data(80), dst_mac=self._ext_mac()))
            self._emit(t + 0.012 + self._delay(s, e), N.to_client(N.DOT_IP, TCP(sport=853, dport=sp, flags="PA", seq=1, ack=81) / N.tls_data(120), ttl=60))
            return
        qid, sp = r.randint(1, 65535), r.randint(30000, 60000)
        self._emit(t, N.dns_query(qid, sp, name))
        if self._fault_on(s, e, "dns_failure") and r.random() < min(1.0, 0.7 * self.i + 0.2):
            m["dnsfail"] += 1
            if r.random() < 0.5:
                self._emit(t + 0.004, N.dns_answer(qid, sp, name, None, rcode=2))      # SERVFAIL
            # 나머지 절반은 응답 없음
            if not extra:
                for _ in range(int(2 * self.i)):                                         # 앱이 다시 조회
                    self._dns_lookup(s, e, extra=True)
            return
        if self.spec.id == "dns_spoof" and self.active(s) and r.random() < min(1.0, self.i):
            # 공격자가 DNS 서버(10.77.0.53)를 사칭해 진짜보다 먼저 가짜 응답을 보냄 (실제 MAC 은 공격자 것)
            self._emit(t + 0.001, N.dns_answer(qid, sp, name, N.FAKE_IP, src_mac=N.ATTACKER_MAC), self.spec.id)
            m["forged"] += 1
        d = 0.004 + self._delay(s, e)
        self._emit(t + d, N.dns_answer(qid, sp, name, ip))
        m["rtts"].append(d * 1000)

    def _web_session(self, s, e, site):
        r, m = self.rng, self._m
        base = N.SITES[site][1] / 1000
        t0 = s + r.uniform(0, 0.8)
        sp = r.randint(49152, 65000)
        seq, sseq = r.randint(1, 2**31), r.randint(1, 2**31)
        mac = self._ext_mac()
        self._emit(t0, N.from_client(site, TCP(sport=sp, dport=443, flags="S", seq=seq, window=65535), dst_mac=mac))
        rtt1 = base + r.uniform(0, 0.004) + self._delay(s, e)
        m["rtts"].append(rtt1 * 1000)
        t1 = t0 + rtt1
        self._emit(t1, N.to_client(site, TCP(sport=443, dport=sp, flags="SA", seq=sseq, ack=seq + 1, window=65160)))
        self._emit(t1 + 0.0004, N.from_client(site, TCP(sport=sp, dport=443, flags="A", seq=seq + 1, ack=sseq + 1, window=2058), dst_mac=mac))
        req = N.from_client(site, TCP(sport=sp, dport=443, flags="PA", seq=seq + 1, ack=sseq + 1) / N.tls_data(300), dst_mac=mac)
        self._emit(t1 + 0.001, req)
        if r.random() < self._loss_p(s, e):
            self._emit(t1 + 0.201, req)        # 응답이 없어 같은 SEQ 로 재전송 (TCP 재전송)
            m["loss"] += 1
            t1 += 0.2
        t2 = t1 + 0.001 + base + self._delay(s, e)
        nseg = r.randint(3, 5)
        for k in range(nseg):
            self._emit(t2 + k * 0.002, N.to_client(site, TCP(sport=443, dport=sp, flags="PA", seq=sseq + 1 + k * 1300, ack=seq + 301) / N.tls_data(1300)))
        self._emit(t2 + nseg * 0.002 + 0.0003, N.from_client(site, TCP(sport=sp, dport=443, flags="A", seq=seq + 301, ack=sseq + 1 + nseg * 1300), dst_mac=mac))

    def _intranet(self, s, e):
        """내부 서버(NAS 등) 접속. Connection Failure 시나리오에서는 서버가 응답을 멈춘다."""
        r, m = self.rng, self._m
        t0 = s + r.uniform(0, 0.5)
        sp = r.randint(49152, 65000)
        seq = r.randint(1, 2**31)
        syn = N.from_client(N.SERVER_IP, TCP(sport=sp, dport=443, flags="S", seq=seq, window=65535))
        self._emit(t0, syn)
        if self._fault_on(s, e, "conn_failure"):
            self._emit(t0 + 1.0, syn)          # SYN 재전송 (응답 없음)
            m["connfail"] += 1
            return
        rtt = 0.001 + self._delay(s, e)
        m["rtts"].append(rtt * 1000)
        sseq = r.randint(1, 2**31)
        self._emit(t0 + rtt, N.to_client(N.SERVER_IP, TCP(sport=443, dport=sp, flags="SA", seq=sseq, ack=seq + 1), ttl=64))
        self._emit(t0 + rtt + 0.0003, N.from_client(N.SERVER_IP, TCP(sport=sp, dport=443, flags="A", seq=seq + 1, ack=sseq + 1)))

    # ── 공격 ──
    def _atk_syn_flood(self, s, e):
        r, m = self.rng, self._m
        for k in range(max(1, round(25 * self.i))):
            t = s + r.random()
            sp, sq = r.randint(1024, 65535), r.randint(1, 2**31)
            self._emit(t, N.to_client(N.EXT_ATTACKER, TCP(sport=sp, dport=80, flags="S", seq=sq, window=1024), ttl=48), self.spec.id)
            if N.EXT_ATTACKER not in e.host_blocked:   # 가상 방화벽: 들어온 SYN 은 캡처되지만 응답하지 않음
                self._emit(t + 0.0002, N.from_client(N.EXT_ATTACKER, TCP(sport=80, dport=sp, flags="SA", seq=r.randint(1, 2**31), ack=sq + 1),
                                                     dst_mac=self._ext_mac()), self.spec.id)
                m["halfopen"] += 1

    def _atk_port_scan(self, s, e):
        r, m = self.rng, self._m
        blocked = N.ATTACKER_IP in e.host_blocked
        for k in range(max(1, round(15 * self.i))):
            t = s + r.random()
            port, sp = self.scan_port, r.randint(40000, 60000)
            self.scan_port = self.scan_port % 1024 + 1
            self._emit(t, N.to_client(N.ATTACKER_IP, TCP(sport=sp, dport=port, flags="S", seq=r.randint(1, 2**31), window=1024), ttl=64), self.spec.id)
            if not blocked:
                self._emit(t + 0.0002, N.from_client(N.ATTACKER_IP, TCP(sport=port, dport=sp, flags="RA", seq=0, ack=1)), self.spec.id)
                m["exposed"] += 1
        for k in range(max(1, round(5 * self.i))):
            t = s + r.random()
            port, sp = 2000 + self.scan_port + k, r.randint(40000, 60000)
            self._emit(t, N.to_client(N.ATTACKER_IP, UDP(sport=sp, dport=port) / b"probe", ttl=64), self.spec.id)
            if not blocked:
                self._emit(t + 0.0002, N.icmp_port_unreachable(N.ATTACKER_IP, sp, port), self.spec.id)
                m["exposed"] += 1

    def _atk_repeated(self, s, e):
        r, m = self.rng, self._m
        for k in range(max(1, round(10 * self.i))):
            t = s + r.random()
            sp = r.randint(40000, 60000)
            self._emit(t, N.to_client(N.ATTACKER_IP, TCP(sport=sp, dport=3389, flags="S", seq=r.randint(1, 2**31)), ttl=64), self.spec.id)
            if N.ATTACKER_IP not in e.host_blocked:
                self._emit(t + 0.0002, N.from_client(N.ATTACKER_IP, TCP(sport=3389, dport=sp, flags="RA", seq=0, ack=1)), self.spec.id)
                m["refused"] += 1

    def _atk_ip_spoof(self, s, e):
        if e.ingress_filter:
            return   # 가상 인그레스 필터링: 위조 출발지 패킷이 LAN 에 들어오지 못함
        r, m = self.rng, self._m
        n = max(1, round(3 * self.i))
        for k in range(n):
            t = s + r.random()
            kind = (s * 7 + k) % 5
            if kind == 0:     # 공격자가 내 주소로 위조해 서버를 공격 → 서버의 SYN-ACK 가 나에게 옴(백스캐터)
                pkt = N.to_client(N.SERVER_IP, TCP(sport=445, dport=r.randint(1024, 65535), flags="SA", seq=r.randint(1, 2**31), ack=r.randint(1, 2**31)), ttl=64)
            elif kind == 1:   # DNS 서버 IP 를 사칭 (실제 MAC 은 공격자)
                pkt = N.to_client(N.DNS_IP, UDP(sport=r.randint(1024, 65535), dport=r.randint(1024, 65535)) / b"x", ttl=64, src_mac=N.ATTACKER_MAC)
            elif kind == 2:   # 내 주소를 출발지로 한 다른 장치의 프레임
                pkt = Ether(src=N.ATTACKER_MAC, dst=N.CLIENT_MAC) / IP(src=N.CLIENT_IP, dst=N.CLIENT_IP, ttl=64) / TCP(sport=139, dport=139, flags="S")
            elif kind == 3:   # 예약 주소(240.0.0.0/4) 출발지
                pkt = N.to_client("240.0.0.%d" % r.randint(1, 250), UDP(sport=r.randint(1024, 65535), dport=161) / b"x", ttl=50)
            else:             # 잘 아는 사이트 IP 를 사칭하지만 경로 길이(TTL)가 전혀 다름
                site = r.choice(list(N.SITES))
                pkt = N.to_client(site, TCP(sport=443, dport=r.randint(1024, 65535), flags="R", seq=r.randint(1, 2**31)), ttl=120)
            self._emit(t, pkt, self.spec.id)
            m["spoofed"] += 1

    def _atk_arp_spoof(self, s, e):
        r, m = self.rng, self._m
        for k in range(max(1, round(2 * self.i))):
            t = s + r.random()
            self._emit(t, N.arp_reply(N.GW_IP, N.ATTACKER_MAC), self.spec.id)
            if not e.static_arp:
                self.gw_mac_cache = N.ATTACKER_MAC   # 내 컴퓨터의 ARP 캐시가 오염됨
        if self.gw_mac_cache == N.ATTACKER_MAC:
            # 이번 초에 외부로 나간 내 프레임 중 공격자 MAC 으로 간 것을 센다 (생성 후 집계)
            pass

    # 집계 보정: 공격자 MAC 으로 간 프레임 수는 패킷을 꺼낼 때 계산
    def count_redirected(self, batch) -> int:
        return sum(1 for _, p, _ in batch if p.haslayer(Ether) and p[Ether].src == N.CLIENT_MAC and p[Ether].dst == N.ATTACKER_MAC)
