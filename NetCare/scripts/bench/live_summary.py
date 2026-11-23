"""실측 한 건 요약 — perf_monitor.py 결과(perf.csv · diag.jsonl)와 NetCare DB 로 메모리·처리·누락·알림을 정리한다.

    python scripts/bench/live_summary.py --dir <측정 폴더> [--db <netcare.db>] [--out summary.json] [--md summary.md]
"""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from collections import Counter
from pathlib import Path

SECURITY = {"ip_spoof_suspect", "tcp_injection", "udp_replay", "checksum_error", "arp_spoof", "dns_spoof_suspect"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--db", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--md", default="")
    a = ap.parse_args()
    d = Path(a.dir)
    perf = list(csv.DictReader((d / "perf.csv").open()))
    diag = [json.loads(x) for x in (d / "diag.jsonl").read_text().splitlines() if x.strip()] if (d / "diag.jsonl").exists() else []
    rss = [float(r["rss_mb"]) for r in perf if r.get("rss_mb")]
    cpu = [float(r["cpu_pct"]) for r in perf if r.get("cpu_pct")]
    t = [int(r["t"]) for r in perf]
    res = {"duration_min": round(t[-1] / 60, 1) if t else 0, "samples": len(perf),
           "processed": int(perf[-1]["processed"]) if perf else 0, "app_dropped": int(perf[-1]["dropped"]) if perf else 0,
           "cpu_avg": round(sum(cpu) / len(cpu), 1) if cpu else None, "cpu_max": max(cpu) if cpu else None,
           "rss_first": rss[0] if rss else None, "rss_last": rss[-1] if rss else None, "rss_max": max(rss) if rss else None,
           "rss_by_10min": [float(r["rss_mb"]) for r in perf if int(r["t"]) % 600 < 10 and r.get("rss_mb")],
           "db_lag_p95": None}
    lags = sorted(float(r["db_lag_s"]) for r in perf if r.get("db_lag_s"))
    if lags:
        res["db_lag_p95"] = lags[int(len(lags) * 0.95) - 1]
    caps = [x["capture"] for x in diag if x.get("capture")]
    if caps:
        c = caps[-1]
        res["capture"] = {k: c.get(k) for k in ("kernel_method", "app_captured", "app_processed", "app_dropped", "kernel_recv", "kernel_drop",
                                                "kernel_ifdrop", "nic_rx_packets", "nic_rx_dropped", "nic_rx_missed")}
        res["capture"]["intervals_with_kernel_drop"] = sum(1 for x in caps if (x.get("d_kernel_drop") or 0) > 0)
        res["capture"]["intervals"] = len(caps)
    if diag:
        last = diag[-1]["objects"]
        res["objects_end"] = dict(sorted(((k, v) for k, v in last.items() if "[*]" not in k), key=lambda kv: -kv[1])[:10])
    db = Path(a.db) if a.db else (d / "data" / "netcare.db")
    if db.exists():
        con = sqlite3.connect(db)
        rows = con.execute("SELECT type, src, detected_at, evidence, session_id FROM anomalies ORDER BY detected_at").fetchall()
        res["alerts"] = dict(Counter(r[0] for r in rows if r[4] is not None))
        res["probe_alerts"] = dict(Counter(r[0] for r in rows if r[4] is None))
        res["security_alerts"] = [{"type": r[0], "at": r[2], "evidence": json.loads(r[3] or "{}")} for r in rows if r[0] in SECURITY]
    text = json.dumps(res, ensure_ascii=False, indent=1)
    print(text)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    if a.md:
        c = res.get("capture") or {}
        md = [f"# 실측 요약 ({res['duration_min']}분)", "",
              "| 항목 | 값 |", "|---|---|",
              f"| 처리한 패킷 | {res['processed']:,} |",
              f"| 응용 단계 누락 | {res['app_dropped']:,} |",
              f"| 커널 수신 / 누락 ({c.get('kernel_method')}) | {c.get('kernel_recv')} / {c.get('kernel_drop')} (누락 구간 {c.get('intervals_with_kernel_drop')}/{c.get('intervals')}) |",
              f"| NIC 수신 / 누락 | {c.get('nic_rx_packets')} / {c.get('nic_rx_dropped')} |",
              f"| CPU 평균 / 최대 | {res['cpu_avg']}% / {res['cpu_max']}% |",
              f"| RSS 시작 → 끝 (최대) | {res['rss_first']} → {res['rss_last']} MB ({res['rss_max']} MB) |",
              f"| RSS 10분 간격 | {res['rss_by_10min']} |",
              f"| DB 반영 지연 p95 | {res['db_lag_p95']} s |",
              f"| 알림 (세션) | {res.get('alerts')} |",
              f"| 보안 알림 | {len(res.get('security_alerts') or [])}건 |", ""]
        Path(a.md).write_text("\n".join(md), encoding="utf-8")


if __name__ == "__main__":
    main()
