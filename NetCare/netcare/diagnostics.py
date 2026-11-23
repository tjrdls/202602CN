"""메모리 진단 (읽기 전용) — 장시간 실행 시 어디서 메모리가 늘어나는지 찾기 위한 계측.

- 프로세스 RSS (psutil)
- tracemalloc 현재/최대 (환경 변수 NETCARE_TRACEMALLOC=프레임수 로 서버를 시작했을 때만)
- 엔진이 들고 있는 주요 자료구조의 원소 수 (탐지기·고급 탐지·무결성·CrowdSec 호환·암호화 분석·통계·큐)
- 선택: tracemalloc 상위 할당 위치 (파일:줄)

이 모듈은 값을 읽기만 하고 어떤 상태도 바꾸지 않는다.
"""
from __future__ import annotations

import gc
import os
import time
import tracemalloc
from collections import deque

_CONTAINERS = (dict, list, set, frozenset, deque)


def start_tracemalloc_from_env() -> int:
    """NETCARE_TRACEMALLOC=N 이면 N 프레임으로 tracemalloc 시작. 시작했으면 프레임 수, 아니면 0."""
    try:
        n = int(os.environ.get("NETCARE_TRACEMALLOC", "0") or 0)
    except ValueError:
        n = 0
    if n > 0 and not tracemalloc.is_tracing():
        tracemalloc.start(n)
    return n if tracemalloc.is_tracing() else 0


def _deep_len(v) -> int:
    """컨테이너 안의 컨테이너 원소 수까지 한 단계 더 센다 (예: 흐름 → deque)."""
    n = 0
    vals = v.values() if isinstance(v, dict) else v
    try:
        for x in vals:
            if isinstance(x, _CONTAINERS):
                n += len(x)
    except RuntimeError:          # 다른 스레드가 바꾸는 중이면 이번 표본은 건너뜀
        return -1
    return n


def container_sizes(obj, prefix: str) -> dict[str, int]:
    out = {}
    if obj is None:
        return out
    for name, v in list(vars(obj).items()):
        if isinstance(v, _CONTAINERS):
            out[f"{prefix}.{name}"] = len(v)
            d = _deep_len(v)
            if d > 0:
                out[f"{prefix}.{name}[*]"] = d
    return out


def engine_objects(engine) -> dict[str, int]:
    det = getattr(engine, "detector", None)
    enc = getattr(engine, "enc", None)
    parts = [(det, "det"), (getattr(det, "adv", None), "adv"), (getattr(det, "integ", None), "integ"),
             (getattr(det, "compat", None), "compat"), (enc, "enc"), (getattr(enc, "reasm", None), "enc.reasm"),
             (getattr(enc, "quic", None), "enc.quic"), (getattr(enc, "dns", None), "enc.dns"),
             (getattr(engine, "stats", None), "stats")]
    out: dict[str, int] = {}
    for o, p in parts:
        out.update(container_sizes(o, p))
    out["engine.names"] = len(getattr(engine, "names", {}) or {})
    out["engine.active"] = len(getattr(engine, "active", {}) or {})
    q = getattr(engine, "queue", None)
    if q is not None:
        out["engine.queue"] = q.qsize()
    return out


def memory_report(engine, top: int = 0) -> dict:
    rep: dict = {"ts": time.time()}
    try:
        import psutil
        p = psutil.Process()
        mi = p.memory_info()
        rep["rss_mb"] = round(mi.rss / 1e6, 1)
        rep["vms_mb"] = round(mi.vms / 1e6, 1)
        rep["threads"] = p.num_threads()
    except Exception:
        pass
    rep["gc_counts"] = list(gc.get_count())
    rep["tracemalloc"] = tracemalloc.is_tracing()
    if tracemalloc.is_tracing():
        cur, peak = tracemalloc.get_traced_memory()
        rep["traced_mb"] = round(cur / 1e6, 2)
        rep["traced_peak_mb"] = round(peak / 1e6, 2)
        if top > 0:
            snap = tracemalloc.take_snapshot().filter_traces((tracemalloc.Filter(False, tracemalloc.__file__),))
            stats = snap.statistics("lineno")[:top]
            rep["top"] = [{"where": f"{s.traceback[0].filename.split('site-packages/')[-1].split('NetCare/')[-1]}:{s.traceback[0].lineno}",
                           "kb": round(s.size / 1024, 1), "count": s.count} for s in stats]
    rep["objects"] = engine_objects(engine)
    return rep
