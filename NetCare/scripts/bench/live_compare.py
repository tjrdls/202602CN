"""수정 전/후 NetCare 를 같은 인터페이스에서 동시에 실측한 결과를 같은 시간 구간으로 비교한다.

    python scripts/bench/live_compare.py --before <dir> --after <dir> [--out result.json]

각 dir: data/netcare.db, perf.csv(+perf_part2.csv), diag.jsonl (scripts/perf_monitor.py 출력)
- 메모리: 시간대별 RSS·tracemalloc 현재값, 주요 자료구조 원소 수 (같은 벽시계 시각 기준)
- 알림: 두 실행이 모두 캡처 중이던 겹치는 구간의 유형별 건수, 보안 알림(스푸핑·주입·재전송) 목록
- 누락: 응용 단계(큐) 누락, (수정 후만) 커널·NIC 단계 누락
"""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from collections import Counter
from pathlib import Path

SECURITY = {"ip_spoof_suspect", "tcp_injection", "udp_replay", "checksum_error", "arp_spoof", "dns_spoof_suspect"}


def load_diag(d: Path):
    rows = []
    for line in (d / "diag.jsonl").read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def load_perf(d: Path):
    out = []
    for name in ("perf.csv", "perf_part2.csv"):
        p = d / name
        if p.exists():
            out += list(csv.DictReader(p.open()))
    return out


def session(d: Path):
    c = sqlite3.connect(d / "data" / "netcare.db")
    c.row_factory = sqlite3.Row
    s = dict(c.execute("SELECT * FROM sessions ORDER BY id LIMIT 1").fetchone())
    s["started"] = s["started_at"]
    return c, s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    B, A = Path(a.before), Path(a.after)
    cb, sb = session(B)
    ca, sa = session(A)
    db_, da_ = load_diag(B), load_diag(A)
    t0 = max(sb["started"], sa["started"])
    t1 = min(db_[-1]["ts"], da_[-1]["ts"])
    res = {"overlap": {"start": t0, "end": t1, "hours": round((t1 - t0) / 3600, 2)},
           "before_started": sb["started"], "after_started": sa["started"]}

    def mem_series(rows, start):
        out = []
        for h in range(0, 8):
            target = start + h * 3600
            cand = [r for r in rows if abs(r["ts"] - target) <= 30]
            if not cand:
                continue
            r = min(cand, key=lambda r: abs(r["ts"] - target))
            objs = {k: v for k, v in r["objects"].items() if "[*]" not in k}
            out.append({"hour": h, "rss_mb": r.get("rss_mb"), "traced_mb": r.get("traced_mb"),
                        "top_objects": sorted(objs.items(), key=lambda kv: -kv[1])[:8]})
        return out
    res["memory_before"] = mem_series(db_, sb["started"])
    res["memory_after"] = mem_series(da_, sa["started"])
    for key, rows in (("before", db_), ("after", da_)):
        tr = [r.get("traced_mb") for r in rows if r.get("traced_mb") is not None]
        rss = [r.get("rss_mb") for r in rows if r.get("rss_mb") is not None]
        res[f"memory_{key}_summary"] = {"samples": len(rows), "traced_first": tr[0], "traced_last": tr[-1], "traced_max": max(tr),
                                        "rss_first": rss[0], "rss_last": rss[-1], "rss_max": max(rss),
                                        "duration_h": round((rows[-1]["ts"] - rows[0]["ts"]) / 3600, 2)}

    def alerts(c, lo, hi):
        rows = [dict(r) for r in c.execute("SELECT id,type,severity,detected_at,src,dst,evidence FROM anomalies WHERE detected_at BETWEEN ? AND ? AND session_id IS NOT NULL ORDER BY detected_at", (lo, hi))]
        return rows
    for key, c in (("before", cb), ("after", ca)):
        al = alerts(c, t0, t1)
        res[f"alerts_{key}"] = dict(Counter(r["type"] for r in al))
        res[f"security_{key}"] = [{"type": r["type"], "at": r["detected_at"], "evidence": json.loads(r["evidence"] or "{}")} for r in al if r["type"] in SECURITY]
        probe = [dict(r) for r in c.execute("SELECT type FROM anomalies WHERE detected_at BETWEEN ? AND ? AND session_id IS NULL", (t0, t1))]
        res[f"probe_alerts_{key}"] = dict(Counter(r["type"] for r in probe))
    pb, pa = load_perf(B), load_perf(A)
    res["app_dropped_before"] = max(int(r["dropped"]) for r in pb)
    res["app_dropped_after"] = max(int(r["dropped"]) for r in pa)
    res["processed_before"] = max(int(r["processed"]) for r in pb)
    res["processed_after"] = max(int(r["processed"]) for r in pa)
    caps = [r["capture"] for r in da_ if r.get("capture")]
    if caps:
        last = caps[-1]
        res["capture_after_last"] = last
        bursts = [c for c in caps if (c.get("d_kernel_drop") or 0) > 0 or (c.get("d_app_dropped") or 0) > 0]
        res["capture_after_drop_intervals"] = len(bursts)
        res["capture_after_intervals"] = len(caps)
    hist = [json.loads(r["data"]) for r in ca.execute("SELECT data FROM capture_stats ORDER BY ts")]
    res["capture_rows_in_db"] = len(hist)
    print(json.dumps({k: v for k, v in res.items() if not k.startswith("security_") and not k.startswith("memory_b") and not k.startswith("memory_a")},
                     ensure_ascii=False, indent=1))
    for key in ("before", "after"):
        print(f"--- 보안 알림 ({key}) {len(res['security_' + key])}건")
        for s in res["security_" + key]:
            ev = s["evidence"]
            print("  ", s["type"], round(s["at"] - t0), ev.get("indicators"), ev.get("sample_sources") or ev.get("flows") or ev.get("flow"))
        print(f"--- 메모리 ({key})")
        for m in res["memory_" + key]:
            print(f"   {m['hour']}h rss={m['rss_mb']} traced={m['traced_mb']} {m['top_objects'][:5]}")
        print("   요약", res[f"memory_{key}_summary"])
    if a.out:
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
