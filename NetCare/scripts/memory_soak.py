"""가속 메모리 소크 테스트 — 몇 시간 분량의 '흐름 교체(churn)'를 몇 분 안에 상태 보존 모듈에 흘려 넣는다.

    python scripts/memory_soak.py [--hours 6] [--out docs/benchmark/memory_soak.json]

네트워크 전송 없음. 파서는 상태가 없으므로 건너뛰고, 상태를 들고 있는 모듈(암호화 분석·탐지기·통계·이름표)에
실제 파서가 만드는 것과 같은 모양의 레코드를 넣는다. 시뮬레이션 시각 10분마다 tracemalloc 현재 메모리와
주요 자료구조 원소 수를 기록한다. 장시간 실행에서 '계속 자라는' 자료구조를 찾는 것이 목적이다.

흐름 교체 양(초당): 새 TCP 연결 3개(그중 1개 TLS ClientHello), DNS 질의·응답 1쌍(매번 새 이름),
QUIC 연결 0.5개, 처음 보는 외부 주소에서 오는 수신 패킷 2개(스캐너·백스캐터 형태), 내 서버로 오는 연결 0.3개.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netcare import diagnostics                       # noqa: E402
from netcare.analysis.stats import LiveStats          # noqa: E402
from netcare.config import DetectionConfig            # noqa: E402
from netcare.detection.detector import Detector       # noqa: E402
from netcare.encrypted.analyzer import EncryptedAnalyzer  # noqa: E402
from tests.test_quic import crypto, protect           # noqa: E402
from tests.tls_builders import chrome_hello, record   # noqa: E402

ME, MY_MAC, GW_MAC = "192.168.1.10", "02:00:00:00:00:10", "02:00:00:00:00:01"
BASE = {"length": 60, "source": "live", "first_layer": "Ether", "ethertype": "0x0800 (IPv4)", "ip_version": 4, "ip_len": 46,
        "flags": None, "seq": None, "ack": None, "window": 65535, "udp_len": None, "payload_len": 0, "arp_op": None, "arp_hwsrc": None,
        "icmp_type": None, "icmp_code": None, "dns_qname": None, "dns_qtype": None, "dns_qr": None, "dns_rcode": None, "dns_id": None,
        "dns_answers": None, "tls": None, "service": None, "service_desc": None, "service_port": None, "csum": None, "udp_head": None,
        "rtp": None, "http": None, "ftp_code": None, "info": "", "friendly": ""}


def rec(ts, src, dst, proto, sport, dport, up, **kw):
    r = dict(BASE)
    r.update(ts=ts, src=src, dst=dst, proto=proto, sport=sport, dport=dport, direction="up" if up else "down",
             src_mac=MY_MAC if up else GW_MAC, dst_mac=GW_MAC if up else MY_MAC, ttl=64 if up else 52,
             service_port=dport if up else sport)
    r.update(kw)
    if not up and r.get("csum") is None:
        r["csum"] = {"ip": True, "l4": True, "l4_proto": proto}
    return r


class Soak:
    def __init__(self, seed=7):
        self.rng = random.Random(seed)
        self.det = Detector(DetectionConfig(), {ME}, {MY_MAC}, gateway_ip="192.168.1.1")
        self.enc = EncryptedAnalyzer()
        self.stats = LiveStats()
        self.names: dict[str, str] = {}
        self.sport = 30000
        self.n = 0
        self.hellos = [record(chrome_hello(f"site{i}.example")) for i in range(20)]
        self.quics = [protect(crypto(0, chrome_hello(f"q{i}.example", alpns=("h3",))[:900]), bytes([i]) * 8, b"\x02" * 8, pad_to=1250)
                      for i in range(10)]

    def ip(self):
        return f"{self.rng.randint(11, 199)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"

    def feed(self, r, payload=None):
        self.enc.process(r, payload)
        self.det.observe(r)
        self.stats.add(r)
        if r.get("dns_answers") and r.get("dns_qname"):          # Engine._handle_packet 의 이름표 갱신과 같은 규칙
            for a in r["dns_answers"]:
                if len(self.names) >= 20000:
                    for old in list(self.names)[:2000]:
                        self.names.pop(old, None)
                self.names[a] = r["dns_qname"]
        self.n += 1

    def tcp_conn(self, t, tls):
        dst, sp = self.ip(), self.next_port()
        self.feed(rec(t, ME, dst, "TCP", sp, 443, True, flags="S", seq=1000))
        self.feed(rec(t + 0.02, dst, ME, "TCP", 443, sp, False, flags="SA", seq=5000, ack=1001))
        self.feed(rec(t + 0.03, ME, dst, "TCP", sp, 443, True, flags="A", seq=1001, ack=5001))
        if tls:
            h = self.rng.choice(self.hellos)
            self.feed(rec(t + 0.04, ME, dst, "TCP", sp, 443, True, flags="PA", seq=1001, ack=5001, payload_len=len(h), length=len(h) + 54), h)
        seq = 5001
        for k in range(6):
            self.feed(rec(t + 0.05 + k * 0.01, dst, ME, "TCP", 443, sp, False, flags="A", seq=seq, ack=1001, payload_len=1400, length=1454),
                      b"\x17\x03\x03" + b"\x00" * 40)
            seq += 1400
        self.feed(rec(t + 0.2, ME, dst, "TCP", sp, 443, True, flags="FA", seq=1600, ack=seq))
        self.feed(rec(t + 0.22, dst, ME, "TCP", 443, sp, False, flags="FA", seq=seq, ack=1601))

    def next_port(self):
        self.sport = 30000 + (self.sport - 29999) % 30000
        return self.sport

    def dns(self, t):
        name, sp, did = f"n{self.n}.example.com", self.next_port(), self.rng.randint(0, 65535)
        self.feed(rec(t, ME, "192.168.1.1", "UDP", sp, 53, True, dns_id=did, dns_qr=0, dns_qname=name, dns_qtype=1))
        self.feed(rec(t + 0.01, "192.168.1.1", ME, "UDP", 53, sp, False, dns_id=did, dns_qr=1, dns_qname=name, dns_qtype=1, dns_rcode=0,
                      dns_answers=[self.ip()], src_mac=GW_MAC))

    def quic(self, t):
        dst, sp = self.ip(), self.next_port()
        q = self.rng.choice(self.quics)
        self.feed(rec(t, ME, dst, "UDP", sp, 443, True, payload_len=len(q), length=len(q) + 42), q)
        for k in range(4):
            self.feed(rec(t + 0.03 + k * 0.01, dst, ME, "UDP", 443, sp, False, payload_len=1200, length=1242), b"\x41" + b"\x00" * 30)

    def inbound_noise(self, t):
        src = self.ip()
        fl = self.rng.choice(["S", "SA", "R", "A"])
        self.feed(rec(t, src, ME, "TCP", self.rng.randint(1024, 65535), self.rng.choice([22, 80, 443, 3389, 8080]), False, flags=fl,
                      seq=self.rng.getrandbits(32), ack=0, ttl=self.rng.randint(40, 120)))

    def server_conn(self, t):
        src, sp = self.ip(), self.rng.randint(1024, 65535)
        self.feed(rec(t, src, ME, "TCP", sp, 8080, False, flags="S", seq=1, service_port=8080))
        self.feed(rec(t + 0.01, ME, src, "TCP", 8080, sp, True, flags="SA", seq=9, ack=2, service_port=8080))   # 상대가 ACK 를 안 보냄

    def run(self, hours: float, every_min: int = 10):
        t0 = 1_700_000_000.0
        total = int(hours * 3600)
        rows = []
        wall = time.perf_counter()
        for s in range(total):
            t = t0 + s
            for i in range(3):
                self.tcp_conn(t + i * 0.3, tls=(i == 0))
            self.dns(t + 0.5)
            if s % 2 == 0:
                self.quic(t + 0.6)
            for i in range(2):
                self.inbound_noise(t + 0.7 + i * 0.1)
            if s % 10 < 3:
                self.server_conn(t + 0.9)
            self.det.evaluate(t + 1)
            self.enc.tick(t + 1)
            self.stats.prune(t + 1)
            if (s + 1) % (every_min * 60) == 0:
                cur, peak = tracemalloc.get_traced_memory()
                eng = SimpleNamespace(detector=self.det, enc=self.enc, stats=self.stats, names=self.names, active={}, queue=None)
                objs = diagnostics.engine_objects(eng)
                rows.append({"sim_min": (s + 1) // 60, "records": self.n, "traced_mb": round(cur / 1e6, 2), "peak_mb": round(peak / 1e6, 2),
                             "objects": objs})
                big = sorted(((k, v) for k, v in objs.items()), key=lambda kv: -kv[1])[:6]
                print(f"sim {rows[-1]['sim_min']:4d}분 rec={self.n:>9,} traced={rows[-1]['traced_mb']:7.1f}MB "
                      + " ".join(f"{k}={v}" for k, v in big), flush=True)
        top = tracemalloc.take_snapshot().statistics("lineno")[:25]
        return {"hours": hours, "records": self.n, "wall_sec": round(time.perf_counter() - wall, 1), "checkpoints": rows,
                "top_alloc": [{"where": f"{x.traceback[0].filename.split('NetCare/')[-1].split('site-packages/')[-1]}:{x.traceback[0].lineno}",
                               "kb": round(x.size / 1024, 1), "count": x.count} for x in top]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=6)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    tracemalloc.start(1)
    res = Soak().run(a.hours)
    res["note"] = "가속 시뮬레이션(합성 레코드, 네트워크 전송 없음). 실제 캡처의 메모리 수치가 아니라 자료구조 증가 경향을 보기 위한 시험."
    if a.out:
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        print("saved", a.out)
    for x in res["top_alloc"][:12]:
        print(f"  {x['kb']:>10.1f} KB  {x['count']:>8}  {x['where']}")


if __name__ == "__main__":
    main()
