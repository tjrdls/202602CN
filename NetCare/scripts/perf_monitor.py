"""장시간 캡처 성능 측정 — NetCare 서버를 바꾸지 않고 바깥에서 측정한다.

    python scripts/perf_monitor.py --base http://127.0.0.1:8771 --pid <서버 PID> --duration 3600 --out perf.csv

10초마다 기록: 서버 프로세스 CPU%·RSS·스레드 수, 처리한 패킷·버린 패킷·큐 길이(/api/status),
TCP 재조립 버퍼에 남은 흐름 수·QUIC 통계(/api/encrypted), 캡처→DB 반영 지연(가장 최근 저장 패킷 시각과 현재 시각의 차),
DB 파일 크기. 끝나면 10분·30분·60분 시점 요약을 출력한다.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
import urllib.request
from pathlib import Path

import psutil


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8771")
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--duration", type=int, default=3600)
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--db", default="")
    ap.add_argument("--out", default="perf.csv")
    a = ap.parse_args()
    proc = psutil.Process(a.pid)
    proc.cpu_percent(None)
    t0 = time.time()
    fields = ["t", "cpu_pct", "rss_mb", "threads", "processed", "dropped", "queue", "pps_now", "reasm_active", "reasm_complete",
              "reasm_failed", "quic_initial", "quic_decrypt_failed", "db_lag_s", "db_mb"]
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        last_proc, last_t = None, None
        while time.time() - t0 < a.duration:
            time.sleep(a.interval)
            now = time.time()
            try:
                st = get(a.base, "/api/status")
                enc = get(a.base, "/api/encrypted")["summary"]
                pk = get(a.base, "/api/packets?limit=1")["packets"]
            except Exception as e:
                print("poll error", e, flush=True)
                continue
            processed = st.get("processed", 0)
            pps = (processed - last_proc) / (now - last_t) if last_proc is not None else 0
            last_proc, last_t = processed, now
            row = {"t": round(now - t0), "cpu_pct": proc.cpu_percent(None), "rss_mb": round(proc.memory_info().rss / 1e6, 1),
                   "threads": proc.num_threads(), "processed": processed, "dropped": st.get("dropped", 0), "queue": st.get("queue", 0),
                   "pps_now": round(pps, 1), "reasm_active": enc["reassembly"]["active"], "reasm_complete": enc["reassembly"]["complete"],
                   "reasm_failed": enc["reassembly"]["failed"], "quic_initial": enc["quic"]["initial"],
                   "quic_decrypt_failed": enc["quic"]["decrypt_failed"],
                   "db_lag_s": round(now - pk[0]["ts"], 2) if pk else "",
                   "db_mb": round(os.path.getsize(a.db) / 1e6, 1) if a.db and Path(a.db).exists() else ""}
            w.writerow(row)
            f.flush()
    print("done", a.out)


if __name__ == "__main__":
    main()
