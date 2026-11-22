"""흐름 상한·메모리·처리량 스트레스 측정 (검증 전용, 네트워크 전송 없음).

    python scripts/stress_limits.py

- 상한이 있는 자료구조에 상한보다 훨씬 많은 흐름을 넣고 최종 크기와 메모리(tracemalloc 최대치)를 잰다
- 파서→암호화 분석→탐지기 처리량(초당 패킷), 엔진+DB 전체 처리량(pcap 가져오기)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.test_quic import crypto, protect          # noqa: E402  (테스트용 패킷 생성기 재사용)
from tests.tls_builders import chrome_hello, record  # noqa: E402


def measure(name, fn):
    tracemalloc.start()
    t0 = time.perf_counter()
    info = fn()
    dt = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    info.update(seconds=round(dt, 2), peak_mb=round(peak / 1e6, 1))
    print(f"{name}: {info}", flush=True)
    return info


def reassembly_limit():
    from netcare.encrypted.reassembly import MAX_STREAMS, TcpReassembler
    r = TcpReassembler()
    head = record(chrome_hello("s.example"))[:300]       # 끝나지 않는 ClientHello 앞부분 → 버퍼에 남음
    n = 100_000
    for i in range(n):
        r.feed((f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", 40000, "203.0.113.5", 443), 1000, head, i * 0.001)
    for i in range(20_000):
        r.feed((f"10.9.{i >> 8 & 255}.{i & 255}", 40001, "203.0.113.5", 443), 5000, b"\x17" * 100, 0.0)   # TLS 머리 아닌 조각(보관)
    return {"flows_fed": n, "streams_after": len(r.streams), "cap": MAX_STREAMS, "evicted": r.stats["evicted"], "orphans_after": len(r.orphans), "orphan_cap": 2048}


def quic_limit():
    from netcare.encrypted.quic import MAX_CONNS, QuicAnalyzer
    q = QuicAnalyzer()
    ch = chrome_hello("q.example", alpns=("h3",))
    n = 12_000
    for i in range(n):
        dcid = i.to_bytes(8, "big")
        q.datagram(protect(crypto(0, ch[:600]), dcid, b"\x01" * 8, pad_to=1250), 1.0, flow=(f"10.0.{i >> 8 & 255}.{i & 255}", 50000, "203.0.113.9", 443))
    return {"connections_fed": n, "conns_after": len(q.conns), "cap": MAX_CONNS, "by_flow": len(q.by_flow)}


def analyzer_flows_limit():
    from netcare.encrypted.analyzer import MAX_FLOWS, EncryptedAnalyzer
    a = EncryptedAnalyzer()
    hello = record(chrome_hello("f.example"))[:400]
    n = 120_000
    for i in range(n):
        rec = {"proto": "TCP", "src": f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", "dst": "203.0.113.5", "sport": 40000, "dport": 443,
               "flags": "PA", "seq": 1000, "ts": i * 0.001, "length": 454, "tls": None, "dns_id": None}
        a.process(rec, hello)
    return {"flows_fed": n, "flow_kind_after": len(a.flow_kind), "cap": MAX_FLOWS, "reasm_streams": len(a.reasm.streams),
            "dns_flows": len(a.dns.flows)}


def detector_limits():
    from netcare.config import DetectionConfig
    from netcare.detection.detector import Detector
    d = Detector(DetectionConfig(), {"192.168.1.10"}, set())
    n = 60_000
    for i in range(n):
        src = f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}"
        r = {"ts": 1_700_000_000 + i * 0.001, "src": src, "dst": "192.168.1.10", "length": 60, "proto": "TCP", "sport": 40000,
             "dport": 80, "flags": "PA", "ttl": 50, "seq": i, "payload_len": 20, "service_port": 80, "direction": "down",
             "http": {"kind": "req", "method": "GET", "uri": f"/p{i}", "host": "", "ua": "x", "referer": ""}, "dns_id": None}
        d.observe(r)
        if i % 1000 == 0:
            d.evaluate(r["ts"])
    return {"flows_fed": n, "integrity_flows": len(d.integ.flows), "integrity_cap": d.integ.MAX_FLOWS,
            "compat_buckets": len(d.compat.buckets), "compat_cap": d.compat.MAX_BUCKETS, "compat_pending": len(d.compat.pending),
            "detector_buckets": len(d.buckets)}


def pipeline_throughput():
    """파서 → 암호화 분석 → 탐지기 (DB 제외) 초당 패킷."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from netcare.capture.parser import parse_packet
    from netcare.config import DetectionConfig
    from netcare.detection.detector import Detector
    from netcare.encrypted.analyzer import EncryptedAnalyzer
    me = "192.168.1.10"
    pk = []
    hello = record(chrome_hello("t.example"))
    for c in range(300):
        sport = 40000 + c
        e = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        pk.append(e / IP(src=me, dst="203.0.113.5") / TCP(sport=sport, dport=443, flags="S", seq=1))
        pk.append(e / IP(src=me, dst="203.0.113.5") / TCP(sport=sport, dport=443, flags="PA", seq=2) / Raw(hello[:1200]))
        pk.append(e / IP(src=me, dst="203.0.113.5") / TCP(sport=sport, dport=443, flags="PA", seq=1202) / Raw(hello[1200:]))
        for k in range(20):
            pk.append(e / IP(src="203.0.113.5", dst=me) / TCP(sport=443, dport=sport, flags="A", seq=k * 1400) / Raw(b"\x17\x03\x03" + os.urandom(1300)))
        pk.append(e / IP(src=me, dst="198.51.100.1") / UDP(sport=50000 + c, dport=53) / Raw(os.urandom(40)))
    pk = [p.__class__(bytes(p)) for p in pk]
    for i, p in enumerate(pk):
        p.time = 1_700_000_000 + i * 0.0005
    a, d = EncryptedAnalyzer(), Detector(DetectionConfig(), {me}, set())
    t0 = time.perf_counter()
    sec = None
    for p in pk:
        r = parse_packet(p, {me}, set(), store_raw=False)
        a.process(r, r.pop("_payload", None))
        d.observe(r)
        s = int(r["ts"])
        if sec != s:
            sec = s
            d.evaluate(s)
    dt = time.perf_counter() - t0
    return {"packets": len(pk), "pps": round(len(pk) / dt), "handshakes": a.snapshot()["handshakes"]["client_hello"]}


def engine_throughput():
    """엔진 전체(DB 저장 포함): pcap 가져오기로 측정."""
    from scapy.utils import wrpcap
    from tests.test_encrypted_analyzer import tls_conn
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    from netcare.capture.engine import Engine
    tmp = Path(tempfile.mkdtemp())
    pk = []
    for c in range(800):
        pk += tls_conn(f"203.0.113.{c % 200 + 1}", f"e{c}.example", cport=30000 + c, t=c * 0.05, split=c % 2 == 0)
    wrpcap(str(tmp / "t.pcap"), pk)
    eng = Engine(ConfigStore(tmp / "config.json"), Database(tmp / "t.db"), run_probe=False)
    t0 = time.perf_counter()
    eng.import_pcap(tmp / "t.pcap", "t.pcap")
    while eng.state == "importing":
        time.sleep(0.05)
    dt = time.perf_counter() - t0
    out = {"packets": len(pk), "pps": round(len(pk) / dt), "processed": eng.processed, "dropped": eng.dropped,
           "sni_confirmed": eng.enc.snapshot()["sni"]["confirmed"]}
    eng.shutdown()
    return out


if __name__ == "__main__":
    res = {}
    for name, fn in [("reassembly_limit", reassembly_limit), ("quic_limit", quic_limit), ("analyzer_flows_limit", analyzer_flows_limit),
                     ("detector_limits", detector_limits), ("pipeline_throughput", pipeline_throughput), ("engine_throughput", engine_throughput)]:
        res[name] = measure(name, fn)
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "benchmark" / "stress_limits.json"
    out.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print("saved", out)
