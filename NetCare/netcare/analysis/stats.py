"""실시간 통계.

모든 값은 실제로 처리된 패킷 레코드에서만 계산한다 (추정치/가짜 값 없음).
- 누적 카운터: 세션 시작 후 전체 패킷 수, 바이트, 프로토콜/IP/포트별 합계
- 초 단위 버킷: 최근 1시간의 시계열 (PPS, 업/다운로드 속도 그래프용)
"""
from __future__ import annotations

import threading
import time
from collections import Counter, defaultdict

PROTO_GROUPS = ("TCP", "UDP", "ICMP", "OTHER")


def proto_group(p: str) -> str:
    if p in ("TCP", "UDP"):
        return p
    if p in ("ICMP", "ICMPv6"):
        return "ICMP"
    return "OTHER"


class LiveStats:
    HISTORY_SEC = 3600
    # 출발지·목적지·포트별 누적 카운터의 키 상한. 넘으면 패킷 수가 적은 쪽부터 절반을 버린다.
    # (가속 소크 시험: 6시간 분량에서 출발지 키 125,279개까지 끝없이 늘었음 → 메모리 증가 원인)
    # 상위 N 목록은 많이 주고받은 IP 라서 그대로 남고, 버린 뒤 '장치 수'는 근사값(unique_approx=True)으로 표시한다.
    MAX_KEYS = 20000

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.started = time.time()
            self.first_ts = None
            self.last_ts = None
            self.packets = 0
            self.bytes = 0
            self.max_size = 0
            self.min_size = None
            self.up_bytes = 0
            self.down_bytes = 0
            self.proto_packets = Counter()
            self.proto_bytes = Counter()
            self.proto_detail = Counter()       # TCP/UDP/ICMP/ICMPv6/ARP/IGMP...
            self.ip_version = Counter()
            self.src_packets = Counter(); self.src_bytes = Counter()
            self.dst_packets = Counter(); self.dst_bytes = Counter()
            self.port_packets = Counter(); self.port_bytes = Counter()
            self.port_label: dict[str, str] = {}
            self.evicted = {"src": 0, "dst": 0, "port": 0}
            self.buckets: dict[int, list] = {}  # sec → [packets, bytes, up, down, tcp, udp, icmp, other]
            self._minute_pending: dict[int, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0, "up": 0, "down": 0,
                                                                         "tcp": 0, "udp": 0, "icmp": 0, "other": 0})

    def add(self, r: dict):
        size = r["length"]
        ts = r["ts"] or time.time()
        g = proto_group(r["proto"])
        with self._lock:
            self.packets += 1
            self.bytes += size
            self.max_size = max(self.max_size, size)
            self.min_size = size if self.min_size is None else min(self.min_size, size)
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
            self.proto_packets[g] += 1
            self.proto_bytes[g] += size
            self.proto_detail[r["proto"]] += 1
            if r.get("ip_version"):
                self.ip_version[f"IPv{r['ip_version']}"] += 1
            if r["src"]:
                self.src_packets[r["src"]] += 1; self.src_bytes[r["src"]] += size
                if len(self.src_packets) > self.MAX_KEYS:
                    self._trim("src", self.src_packets, self.src_bytes)
            if r["dst"]:
                self.dst_packets[r["dst"]] += 1; self.dst_bytes[r["dst"]] += size
                if len(self.dst_packets) > self.MAX_KEYS:
                    self._trim("dst", self.dst_packets, self.dst_bytes)
            if r.get("service_port") is not None:
                key = f"{r['proto']}/{r['service_port']}"
                self.port_packets[key] += 1; self.port_bytes[key] += size
                if key not in self.port_label:
                    self.port_label[key] = r.get("service") or key
                if len(self.port_packets) > self.MAX_KEYS:
                    self._trim("port", self.port_packets, self.port_bytes, self.port_label)
            up = size if r["direction"] == "up" else 0
            down = size if r["direction"] == "down" else 0
            self.up_bytes += up; self.down_bytes += down
            sec = int(ts)
            b = self.buckets.get(sec)
            if b is None:
                b = self.buckets[sec] = [0, 0, 0, 0, 0, 0, 0, 0]
            b[0] += 1; b[1] += size; b[2] += up; b[3] += down
            b[4 + PROTO_GROUPS.index(g)] += 1
            m = self._minute_pending[sec // 60]
            m["packets"] += 1; m["bytes"] += size; m["up"] += up; m["down"] += down; m[g.lower()] += 1

    def _trim(self, kind: str, packets: Counter, nbytes: Counter, extra: dict | None = None):
        keep = self.MAX_KEYS // 2
        drop = [k for k, _ in packets.most_common()[keep:]]
        for k in drop:
            packets.pop(k, None)
            nbytes.pop(k, None)
            if extra is not None:
                extra.pop(k, None)
        self.evicted[kind] += len(drop)

    def prune(self, now: float):
        with self._lock:
            cutoff = int(now) - self.HISTORY_SEC
            for k in [k for k in self.buckets if k < cutoff]:
                del self.buckets[k]

    def pop_minutes(self) -> dict[int, dict]:
        """DB 에 반영할 분 단위 증분을 꺼낸다."""
        with self._lock:
            out = dict(self._minute_pending)
            self._minute_pending.clear()
            return out

    def _rate(self, now: float, seconds: int) -> tuple[float, float, float, float]:
        """직전 `seconds` 개의 '완료된' 초 평균 (pps, bytes/s, up/s, down/s)."""
        end = int(now)
        p = b = u = d = 0
        for s in range(end - seconds, end):
            x = self.buckets.get(s)
            if x:
                p += x[0]; b += x[1]; u += x[2]; d += x[3]
        return p / seconds, b / seconds, u / seconds, d / seconds

    def snapshot(self, now: float | None = None, series_sec: int = 120, top_n: int = 10) -> dict:
        """화면용 스냅샷. now 를 주면(오프라인 분석) 해당 시점 기준으로 계산."""
        now = now if now is not None else time.time()
        with self._lock:
            pps, bps, ups, downs = self._rate(now, 5)
            end = int(now)
            series = []
            for s in range(end - series_sec, end):
                x = self.buckets.get(s) or [0] * 8
                series.append({"t": s, "packets": x[0], "bytes": x[1], "up": x[2], "down": x[3],
                               "tcp": x[4], "udp": x[5], "icmp": x[6], "other": x[7]})
            dur = (self.last_ts - self.first_ts) if self.first_ts and self.last_ts else 0
            return {
                "total_packets": self.packets,
                "total_bytes": self.bytes,
                "avg_size": round(self.bytes / self.packets, 1) if self.packets else 0,
                "max_size": self.max_size,
                "min_size": self.min_size or 0,
                "pps": round(pps, 2),
                "bps": round(bps, 1),
                "up_bps": round(ups, 1),
                "down_bps": round(downs, 1),
                "avg_pps_session": round(self.packets / dur, 2) if dur > 0 else 0,
                "up_bytes": self.up_bytes,
                "down_bytes": self.down_bytes,
                "duration_sec": round(dur, 1),
                "protocols": {k: {"packets": self.proto_packets[k], "bytes": self.proto_bytes[k]} for k in PROTO_GROUPS},
                "protocol_detail": dict(self.proto_detail.most_common()),
                "ip_versions": dict(self.ip_version),
                "top_src": [{"ip": ip, "packets": n, "bytes": self.src_bytes[ip]} for ip, n in self.src_packets.most_common(top_n)],
                "top_dst": [{"ip": ip, "packets": n, "bytes": self.dst_bytes[ip]} for ip, n in self.dst_packets.most_common(top_n)],
                "top_ports": [{"port": k, "label": self.port_label.get(k, k), "packets": self.port_packets[k],
                               "bytes": self.port_bytes[k]} for k, _ in self.port_bytes.most_common(top_n)],
                "series": series,
                "unique_src": len(self.src_packets) + self.evicted["src"],
                "unique_dst": len(self.dst_packets) + self.evicted["dst"],
                "unique_approx": bool(self.evicted["src"] or self.evicted["dst"]),
            }
