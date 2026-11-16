"""네트워크 종합 상태 점수.

점수는 100점에서 시작해, 아래 '실측 근거'가 있을 때만 정해진 만큼 깎는다.
각 감점 항목은 화면의 "왜 이 점수인가요?"에 그대로 표시된다.

| 항목 | 근거 | 감점 |
|---|---|---|
| 진행 중인 이상 징후 | 최근 5분 내 탐지 | 위험 25, 주의 10, 정보 2 (합계 최대 60) |
| 공유기(게이트웨이) 연결 | ping 실측 | 손실률 × 0.4 (최대 40), 평균 지연 100ms↑ 5 / 300ms↑ 15 |
| 외부 인터넷 연결 | ping 실측 | 손실률 × 0.2 (최대 20), 평균 지연 150ms↑ 5 / 400ms↑ 10 |
| DNS 조회 | 실제 조회 | 실패 1건당 10 (최대 20), 평균 500ms↑ 5 |

80점 이상: 정상 / 50~79: 주의 / 50 미만: 위험
측정하지 않은 항목은 감점하지 않고 '측정 대기'로 표시한다.
"""
from __future__ import annotations

import time

SEV_PENALTY = {"danger": 25, "warning": 10, "info": 2}


def status_of(score: int) -> str:
    return "good" if score >= 80 else ("warning" if score >= 50 else "danger")


def compute(active_anomalies: list[dict], probe: dict | None, now: float | None = None, probe_note: str | None = None) -> dict:
    """probe_note: 실측값을 일부러 쓰지 않을 때의 사유 (예: 테스트 데이터 세션)."""
    now = now or time.time()
    wait = probe_note or "측정 대기 중"
    comps = []

    recent = [a for a in active_anomalies if a.get("status") == "active" and now - (a.get("last_seen") or 0) <= 300]
    pen = min(60, sum(SEV_PENALTY.get(a["severity"], 0) for a in recent))
    cnt = {s: sum(1 for a in recent if a["severity"] == s) for s in SEV_PENALTY}
    comps.append({"key": "anomalies", "label": "이상 징후", "penalty": pen,
                  "detail": (f"최근 5분 진행 중: 위험 {cnt['danger']}건, 주의 {cnt['warning']}건, 정보 {cnt['info']}건"
                             if recent else "최근 5분 동안 진행 중인 이상 징후가 없어요"),
                  "measured": True})

    probe = probe or {}
    gw = probe.get("gateway") or {}
    if gw.get("sent"):
        loss = gw.get("loss_pct") or 0
        p = min(40, loss * 0.4)
        avg = gw.get("avg_ms")
        if avg is not None:
            p += 15 if avg >= 300 else (5 if avg >= 100 else 0)
        detail = f"{gw['target']} 손실 {loss:g}%" + (f", 평균 {avg:g}ms" if avg is not None else "")
        comps.append({"key": "gateway", "label": "공유기 연결", "penalty": round(p, 1), "detail": detail, "measured": True})
    else:
        comps.append({"key": "gateway", "label": "공유기 연결", "penalty": 0,
                      "detail": probe_note or gw.get("error") or wait, "measured": False})

    ext = probe.get("external") or {}
    if ext.get("sent"):
        loss = ext.get("loss_pct") or 0
        p = min(20, loss * 0.2)
        avg = ext.get("avg_ms")
        if avg is not None:
            p += 10 if avg >= 400 else (5 if avg >= 150 else 0)
        detail = f"{ext['target']} 손실 {loss:g}%" + (f", 평균 {avg:g}ms" if avg is not None else "")
        comps.append({"key": "external", "label": "인터넷 연결", "penalty": round(p, 1), "detail": detail, "measured": True})
    else:
        comps.append({"key": "external", "label": "인터넷 연결", "penalty": 0,
                      "detail": probe_note or ext.get("error") or wait, "measured": False})

    dns = probe.get("dns") or {}
    if dns.get("tested"):
        p = min(20, dns["failed"] * 10)
        if dns.get("avg_ms") and dns["avg_ms"] >= 500:
            p += 5
        detail = f"{dns['tested']}건 중 {dns['failed']}건 실패" + (f", 평균 {dns['avg_ms']:g}ms" if dns.get("avg_ms") else "")
        comps.append({"key": "dns", "label": "도메인 조회(DNS)", "penalty": p, "detail": detail, "measured": True})
    else:
        comps.append({"key": "dns", "label": "도메인 조회(DNS)", "penalty": 0, "detail": wait, "measured": False})

    score = max(0, round(100 - sum(c["penalty"] for c in comps)))
    st = status_of(score)
    headline = {"good": "네트워크가 안정적이에요", "warning": "확인이 필요한 부분이 있어요", "danger": "네트워크에 문제가 있어요"}[st]
    return {"score": score, "status": st, "headline": headline, "components": comps,
            "measured_items": sum(1 for c in comps if c["measured"]), "computed_at": now}
