"""실험 평가: 1초 단위 혼동 행렬, Precision / Recall / F1 / FPR, 탐지 소요 시간, 조치 전후 비교.

⚠️ 모든 지표는 [합성 데이터] 기준이다. 생성기와 탐지기를 같은 프로젝트에서 설계했으므로
실제 네트워크 성능보다 좋게 나올 수 있다 (화면·리포트에 항상 표기).

정답과 예측 (초 s 마다)
- 탐지는 경계 시각 s 에 직전 W 초를 보고 판단한다. 그래서 공격이 a0 초에 시작하면 정답 '공격 중' 구간은 (a0, a1] 이다.
- 공격이 끝난 뒤 W 초(유예 구간)는 탐지 창에 공격 데이터가 남아 있으므로, 관련 징후는 오탐으로 세지 않는다.
- 예측: 해당 초에 이상 징후가 '진행 중'(detected_at ≤ s ≤ last_seen)이면 1.
- TP: 공격 구간 + 기대 유형 탐지 · FN: 공격 구간 + 기대 유형 없음
- FP: 정상 구간 + 어떤 징후든 있음 (유예 구간에서는 관련 없는 징후만) · TN: 정상 구간 + 징후 없음
- '관련 징후'(acceptable)는 공격 구간에서 TP 도 FP 도 아님 (예: SYN Flood 때 반복 연결 경고)
"""
from __future__ import annotations

import statistics


def _div(a: float, b: float):
    return round(a / b, 4) if b else None


def prf(tp: int, fp: int, fn: int, tn: int) -> dict:
    p = _div(tp, tp + fp)
    r = _div(tp, tp + fn)
    f1 = round(2 * p * r / (p + r), 4) if p and r else (0.0 if (p == 0 or r == 0) and p is not None and r is not None else None)
    return {"precision": p, "recall": r, "f1": f1, "fpr": _div(fp, fp + tn)}


def score(spec, params: dict, anomalies: list[dict], base: float, window_sec: int, stop_sec: int | None = None) -> dict:
    dur, a0, a1 = params["duration"], params["attack_start"], params["attack_end"]
    expected, relevant = set(spec.expected), set(spec.expected) | set(spec.acceptable)
    has_attack = bool(expected)
    iv = [(a["type"], a["detected_at"] - base, a["last_seen"] - base) for a in anomalies]
    tp = fp = fn = tn = 0
    timeline = []
    end = dur + 1 if stop_sec is None else min(dur + 1, stop_sec)
    for s in range(1, dur + 1):
        active = {t for t, d0, d1 in iv if d0 <= s + 1e-6 and s <= d1 + 1e-6}
        if s >= end:   # 조치 이후: 효과로 정답이 바뀌므로 지표에서 제외 (타임라인에는 표시)
            timeline.append({"s": s, "truth": int(has_attack and a0 < s <= a1), "active": sorted(active), "mark": "AFTER"})
            continue
        y = has_attack and a0 < s <= a1
        grace = has_attack and a1 < s <= a1 + window_sec
        p_exp = bool(active & expected)
        p_rel = bool(active & relevant)
        if y:
            if p_exp:
                tp += 1
                mark = "TP"
            else:
                fn += 1
                mark = "FN"
        elif grace:
            if active - relevant:
                fp += 1
                mark = "FP"
            else:
                mark = "-"
        else:
            if active:
                fp += 1
                mark = "FP"
            else:
                tn += 1
                mark = "TN"
        timeline.append({"s": s, "truth": int(y), "active": sorted(active), "mark": mark})
    firsts = [d0 for t, d0, _ in iv if t in expected and d0 > a0 - 1e-6]
    latency = round(min(firsts) - a0, 2) if firsts else None
    false_alerts = []
    for a in anomalies:
        d0 = a["detected_at"] - base
        unrelated = a["type"] not in relevant
        outside = has_attack and not (a0 < d0 <= a1 + window_sec) and a["type"] in relevant
        if (not has_attack) or unrelated or outside:
            false_alerts.append({"type": a["type"], "severity": a["severity"], "at_sec": round(d0, 1),
                                 "reason": "정상 구간 탐지" if (not has_attack or outside) else "공격과 무관한 유형"})
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, **prf(tp, fp, fn, tn),
            "detected": latency is not None if has_attack else None, "latency_sec": latency,
            "false_alerts": false_alerts, "timeline": timeline, "evaluated_until": end - 1}


def before_after(metrics: dict[int, dict], key: str, action_sec: int, attack_end: int, better: str = "lower",
                 attack_start: int = 0) -> dict | None:
    """조치 직전(공격 시작 이후, 최대 10초) vs 조치 2초 뒤부터 10초 (공격 구간 안에서만) 의 지표 평균."""
    def vals(lo, hi):
        out = []
        for s in range(lo, hi):
            v = (metrics.get(s) or {}).get(key)
            if v is not None:
                out.append(v)
        return out
    lo = max(attack_start, action_sec - 10)
    b = vals(lo, action_sec)
    a = vals(action_sec + 2, min(attack_end, action_sec + 12))
    if not b or not a:
        return {"metric": key, "before": statistics.fmean(b) if b else None, "after": statistics.fmean(a) if a else None,
                "improved": None, "note": "비교할 구간이 부족해요 (조치가 공격 종료 직전에 실행됨)"}
    mb, ma = statistics.fmean(b), statistics.fmean(a)
    improved = ma < mb if better == "lower" else ma > mb
    change = None if mb == 0 else round((ma - mb) / mb * 100, 1)
    return {"metric": key, "before": round(mb, 2), "after": round(ma, 2), "change_pct": change, "improved": improved,
            "before_range": [lo, action_sec], "after_range": [action_sec + 2, min(attack_end, action_sec + 12)]}


def aggregate(experiments: list[dict]) -> dict:
    """여러 실험 결과 합산: 시나리오별(macro) + 전체(micro, 초 단위 합)."""
    by = {}
    for e in experiments:
        g = by.setdefault(e["scenario"], {"scenario": e["scenario"], "kind": e["kind"], "runs": 0, "detected": 0, "attack_runs": 0,
                                           "latencies": [], "tp": 0, "fp": 0, "fn": 0, "tn": 0, "false_alert_runs": 0})
        g["runs"] += 1
        for k in ("tp", "fp", "fn", "tn"):
            g[k] += e.get(k) or 0
        if e["kind"] != "baseline":
            g["attack_runs"] += 1
            if e.get("detected"):
                g["detected"] += 1
            if e.get("latency_sec") is not None:
                g["latencies"].append(e["latency_sec"])
        if e.get("false_alerts"):
            g["false_alert_runs"] += 1
    rows = []
    T = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for g in by.values():
        for k in T:
            T[k] += g[k]
        lat = g.pop("latencies")
        rows.append({**g, **prf(g["tp"], g["fp"], g["fn"], g["tn"]),
                     "detection_rate": _div(g["detected"], g["attack_runs"]) if g["attack_runs"] else None,
                     "mean_latency_sec": round(statistics.fmean(lat), 2) if lat else None})
    rows.sort(key=lambda r: (r["kind"] != "baseline", r["kind"], r["scenario"]))
    return {"by_scenario": rows, "overall": {**T, **prf(T["tp"], T["fp"], T["fn"], T["tn"])}, "experiments": len(experiments),
            "note": "합성 데이터 기반 지표입니다. 생성기와 탐지기를 같은 프로젝트에서 설계했으므로 실제 환경보다 좋게 나올 수 있어요."}
