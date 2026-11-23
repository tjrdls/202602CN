"""처리 큐에 쌓인 항목의 메모리: 예전 방식(해석된 Scapy 객체) vs 원시 프레임(RawFrame). 실측 패킷 사용, 네트워크 전송 없음.

    python scripts/bench/queue_memory.py <netcare.db> [--n 50000]
"""
from __future__ import annotations

import argparse
import gc
import queue
import sqlite3
import sys
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import scapy.all  # noqa: E402,F401
from scapy.layers.l2 import Ether  # noqa: E402

from netcare.capture.capstats import RawFrame  # noqa: E402


def fill(rows, make):
    gc.collect()
    tracemalloc.start()
    q = queue.Queue(maxsize=len(rows))
    for ts, raw in rows:
        q.put_nowait((make(raw, ts), "live"))
    cur, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return cur, q


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--n", type=int, default=50000)
    a = ap.parse_args()
    rows = [(ts, bytes(r)) for ts, r in sqlite3.connect(a.db).execute(
        "SELECT ts, raw FROM packets WHERE raw IS NOT NULL ORDER BY ts LIMIT ?", (a.n,))]
    avg = sum(len(r) for _, r in rows) / len(rows)

    def scapy_obj(raw, ts):
        p = Ether(bytes(bytearray(raw)))      # 소켓이 매번 새 바이트를 만드는 것과 같게
        p.time = ts
        return p
    m_old, q1 = fill(rows, scapy_obj)
    del q1
    m_new, q2 = fill(rows, lambda raw, ts: RawFrame(Ether, bytes(bytearray(raw)), ts))
    print(f"패킷 {len(rows):,}개 (평균 {avg:.0f}B)")
    print(f"  Scapy 객체 큐: {m_old / 1e6:7.1f} MB ({m_old / len(rows):,.0f} B/항목)")
    print(f"  원시 프레임 큐: {m_new / 1e6:7.1f} MB ({m_new / len(rows):,.0f} B/항목)  → {m_old / m_new:.1f}배 작음")


if __name__ == "__main__":
    main()
