"""처리 스레드 패킷당 비용 측정 — 실측 원시 패킷을 실제 엔진 처리 경로(해석→파싱→암호화 분석→통계→탐지→DB)로 흘린다.

    python scripts/bench/processing_profile.py --db <netcare.db> [--n 60000] [--profile] [--local 172.16.104.63]

- 패킷 출처: NetCare DB 의 packets.raw (실측 원본 바이트) 또는 --pcap 파일
- 스레드 없이 메인 스레드에서 Engine._handle_packet + 500개마다 _flush (실제 처리 루프와 같은 묶음 크기)
- 단계별 시간: 각 단계를 따로 반복 측정 (해석 / parse_packet / 암호화 분석 / 통계 / 탐지 / DB 저장)
네트워크 전송 없음.
"""
from __future__ import annotations

import argparse
import cProfile
import pstats
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


import scapy.all  # noqa: E402,F401  (실시간 캡처와 같은 계층 바인딩)


def load_frames(a):
    from scapy.layers.l2 import Ether
    from netcare.capture.capstats import RawFrame
    if a.pcap:
        from scapy.utils import RawPcapReader
        out = []
        for data, meta in RawPcapReader(a.pcap):
            out.append(RawFrame(Ether, data, meta.sec + meta.usec / 1e6))
            if len(out) >= a.n:
                break
        return out
    c = sqlite3.connect(a.db)
    rows = c.execute("SELECT ts, raw FROM packets WHERE raw IS NOT NULL ORDER BY ts LIMIT ?", (a.n,)).fetchall()
    return [RawFrame(Ether, bytes(raw), ts) for ts, raw in rows]


def make_engine(local):
    from netcare.capture.engine import Engine
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    d = Path(tempfile.mkdtemp(prefix="procprof-"))
    eng = Engine(ConfigStore(d / "config.json"), Database(d / "t.db"), run_probe=False)
    eng._session_nets = ["172.16.0.0/16"]
    eng._begin("pcap", None, None, "profile", local_ips={local}, local_macs=set())
    return eng


def run_engine(eng, frames):
    batch = []
    t0 = time.perf_counter()
    for f in frames:
        batch.append(eng._handle_packet(f, "pcap"))
        if len(batch) >= 500:
            eng._flush(batch)
            batch = []
    eng._flush(batch)
    return time.perf_counter() - t0


def stages(frames, local):
    """단계별로 따로 돌려 패킷당 µs 를 잰다 (앞 단계 결과를 미리 만들어 둠)."""
    from netcare.analysis.stats import LiveStats
    from netcare.capture.parser import parse_packet
    from netcare.config import DetectionConfig
    from netcare.detection.detector import Detector
    from netcare.encrypted.analyzer import EncryptedAnalyzer
    n = len(frames)
    out = {}
    t = time.perf_counter(); pk = [f.dissect() for f in frames]; out["Scapy 해석"] = time.perf_counter() - t
    t = time.perf_counter(); recs = [parse_packet(p, {local}, set(), source="live", snaplen=2048, store_raw=True) for p in pk]
    out["parse_packet"] = time.perf_counter() - t
    pays = [r.pop("_payload", None) for r in recs]
    a = EncryptedAnalyzer()
    t = time.perf_counter()
    for r, p in zip(recs, pays):
        a.process(r, p)
    out["암호화 분석"] = time.perf_counter() - t
    st = LiveStats()
    t = time.perf_counter()
    for r in recs:
        st.add(r)
    out["통계"] = time.perf_counter() - t
    d = Detector(DetectionConfig(), {local}, set())
    t = time.perf_counter()
    sec = None
    for r in recs:
        d.observe(r)
        s = int(r["ts"])
        if s != sec:
            sec = s
            d.evaluate(s)
    out["탐지(관찰+매초 평가)"] = time.perf_counter() - t
    from netcare.storage.db import Database
    db = Database(Path(tempfile.mkdtemp()) / "x.db")
    sid = db.create_session("pcap", None, None, "x")
    t = time.perf_counter()
    for i in range(0, n, 500):
        db.insert_packets(sid, recs[i:i + 500], 300_000)
    out["DB 저장"] = time.perf_counter() - t
    return {k: round(v / n * 1e6, 1) for k, v in out.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="")
    ap.add_argument("--pcap", default="")
    ap.add_argument("--n", type=int, default=60000)
    ap.add_argument("--local", default="172.16.104.63")
    ap.add_argument("--profile", action="store_true")
    ap.add_argument("--stages", action="store_true")
    a = ap.parse_args()
    frames = load_frames(a)
    print(f"패킷 {len(frames):,}개, 평균 {sum(len(f.data) for f in frames) / len(frames):.0f}B")
    if a.stages:
        st = stages(frames, a.local)
        tot = sum(st.values())
        for k, v in st.items():
            print(f"  {k:18s} {v:7.1f} µs/패킷 ({v / tot:5.1%})")
        print(f"  합계 {tot:.1f} µs → 이론 최대 {1e6 / tot:,.0f} pps")
    eng = make_engine(a.local)
    if a.profile:
        pr = cProfile.Profile()
        pr.enable()
        dt = run_engine(eng, frames)
        pr.disable()
        pstats.Stats(pr).sort_stats("tottime").print_stats(25)
    else:
        dt = run_engine(eng, frames)
    print(f"엔진 처리 경로: {len(frames) / dt:,.0f} pps ({dt / len(frames) * 1e6:.1f} µs/패킷){' (프로파일러 켬)' if a.profile else ''}")
    eng.shutdown()


if __name__ == "__main__":
    main()
