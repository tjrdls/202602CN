"""TCP·QUIC 세션 반복 생성·종료 시험 — 연결을 대량으로 열고 닫은 뒤, 트래픽이 멈추고 시간이 지나면 상태가 비워지는지 본다.

    python scripts/session_churn.py [--out docs/benchmark/session_churn.json]

1단계(생성·종료): 시뮬레이션 30분 동안 초당 TCP 연결 20개(SYN→데이터→FIN)·QUIC 연결 5개를 열고 닫는다.
2단계(정지): 패킷 없이 평가만 15분 진행한다(엔진의 ticker 와 같음).
각 자료구조가 2단계 끝에 0 으로 돌아가는지(시간 만료), 상한까지만 남는지(최근 이력 캐시)를 기록한다.
네트워크 전송 없음.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netcare import diagnostics                 # noqa: E402
from scripts.memory_soak import Soak            # noqa: E402

# 상한까지 남는 것이 설계인 '이력 캐시' (시간 만료 대상이 아님)
CACHES = {"adv.ttl_hist": "출발지별 TTL 분포 (LRU 상한 20,000)", "enc.flow_kind": "암호화 흐름 표시 (LRU 상한 50,000)",
          "engine.names": "IP→도메인 이름표 (상한 20,000)", "stats.src_packets": "세션 누적 통계 (상한 20,000)",
          "stats.src_bytes": "세션 누적 통계", "stats.dst_packets": "세션 누적 통계", "stats.dst_bytes": "세션 누적 통계",
          "stats.port_packets": "세션 누적 통계", "stats.port_bytes": "세션 누적 통계", "stats.port_label": "세션 누적 통계",
          "stats.buckets": "초 단위 그래프 (최근 1시간)", "stats._minute_pending": "DB 반영 대기 (엔진이 0.3초마다 비움)",
          "det.dns_ok": "도메인별 마지막 성공 시각 (상한 20,000)", "enc.events": "최근 분석 결과 (300개)",
          "enc.reasm.orphans": "재조립 대기 조각 (상한 2,048)", "det.local_ips": "설정", "det.local_macs": "설정", "det.local_nets": "설정",
          "compat.hits": "CrowdSec 호환 탐지 이력 (600초 뒤 삭제)", "enc.dns.ddr_clients": "DDR 사용 클라이언트",
          "enc.quic.by_flow": "QUIC 흐름", "enc.reasm.fail_reasons": "실패 사유별 건수", "enc.quic.stats": "QUIC 건수 (고정 항목)"}


def objects(s):
    return diagnostics.engine_objects(SimpleNamespace(detector=s.det, enc=s.enc, stats=s.stats, names=s.names, active={}, queue=None))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--churn-min", type=int, default=30)
    ap.add_argument("--idle-min", type=int, default=15)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    tracemalloc.start(1)
    s = Soak(seed=11)
    t0 = 1_700_000_000.0
    base = objects(s)
    wall = time.perf_counter()
    for sec in range(a.churn_min * 60):
        t = t0 + sec
        for i in range(20):
            s.tcp_conn(t + i * 0.045, tls=(i % 4 == 0))
        for i in range(5):
            s.quic(t + 0.9 + i * 0.01)
        s.det.evaluate(t + 1)
        s.enc.tick(t + 1)
        s.stats.prune(t + 1)
    peak_obj = objects(s)
    peak_mem = tracemalloc.get_traced_memory()[0]
    t_end = t0 + a.churn_min * 60
    for sec in range(a.idle_min * 60):
        s.det.evaluate(t_end + sec + 1)
        s.enc.tick(t_end + sec + 1)
        s.stats.prune(t_end + sec + 1)
    s.stats.pop_minutes()                          # 엔진이 DB 에 반영하며 비우는 것과 같음
    after_obj = objects(s)
    after_mem = tracemalloc.get_traced_memory()[0]
    rows, not_released = [], []
    for k in sorted(peak_obj, key=lambda k: -peak_obj[k]):
        if "[*]" in k or peak_obj[k] < 10:
            continue
        kind = "캐시(상한)" if k in CACHES else "시간 만료 대상"
        row = {"name": k, "before": base.get(k, 0), "peak": peak_obj[k], "after_idle": after_obj.get(k, 0), "kind": kind, "note": CACHES.get(k, "")}
        rows.append(row)
        if kind == "시간 만료 대상" and row["after_idle"] > max(10, 0.05 * row["peak"]):
            not_released.append(k)
    res = {"tcp_connections": a.churn_min * 60 * 20, "quic_connections": a.churn_min * 60 * 5, "records": s.n,
           "wall_sec": round(time.perf_counter() - wall, 1), "traced_mb_peak_phase": round(peak_mem / 1e6, 2),
           "traced_mb_after_idle": round(after_mem / 1e6, 2), "structures": rows, "not_released": not_released,
           "note": "합성 레코드(네트워크 전송 없음). '시간 만료 대상'은 정지 뒤 비워져야 정상, '캐시(상한)'는 상한까지 남는 것이 설계."}
    print(f"TCP {res['tcp_connections']:,} · QUIC {res['quic_connections']:,} 연결, 레코드 {s.n:,}개, {res['wall_sec']}초")
    print(f"추적 메모리: 생성·종료 끝 {res['traced_mb_peak_phase']} MB → 정지 {a.idle_min}분 뒤 {res['traced_mb_after_idle']} MB")
    for r in rows:
        print(f"  {r['name']:30s} 최대 {r['peak']:>8,} → 정지 뒤 {r['after_idle']:>8,}  [{r['kind']}] {r['note']}")
    print("비워지지 않은 시간 만료 대상:", not_released or "없음", flush=True)
    if a.out:
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    sys.exit(1 if not_released else 0)


if __name__ == "__main__":
    main()
