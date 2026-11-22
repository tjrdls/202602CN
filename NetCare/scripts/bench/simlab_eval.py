"""가상 실험실 전체 벤치마크 (현재 코드로 재측정) — 합성 데이터 기준.

    python scripts/bench/simlab_eval.py [출력.json]

시나리오 13종(정상 기준선 포함) × 강도 4단계(0.25, 0.5, 1, 2) × 시드 3개 = 156회.
시나리오·강도별 TP/FP/FN/TN, Precision/Recall/F1/FPR, 탐지율, 최초 탐지 시간과 오탐 알림을 저장한다.
"""
from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from netcare.config import ConfigStore            # noqa: E402
from netcare.simlab import evaluate               # noqa: E402
from netcare.simlab.lab import SimLab              # noqa: E402

INTENSITIES = [0.25, 0.5, 1.0, 2.0]
SEEDS = [1, 2, 3]


def main(out: Path):
    d = Path(tempfile.mkdtemp(prefix="simlab-eval-"))
    lab = SimLab(ConfigStore(d / "config.json"), d)
    t0 = time.time()
    bid = lab.start_benchmark(None, INTENSITIES, SEEDS)
    while lab.bench.get("status") == "running":
        time.sleep(1)
        print(f"\r{lab.bench.get('progress')}/{lab.bench.get('total')}", end="", flush=True)
    print()
    exps = [e for e in lab.experiments(limit=1000, benchmark_id=bid) if e["status"] == "completed"]
    by_int = defaultdict(list)
    for e in exps:
        by_int[(e.get("params") or {}).get("intensity")].append(e)
    per_int = {str(k): evaluate.aggregate(v) for k, v in sorted(by_int.items())}
    lat = defaultdict(list)
    fa = defaultdict(list)
    for e in exps:
        if e.get("latency_sec") is not None:
            lat[(e["scenario"], (e.get("params") or {}).get("intensity"))].append(e["latency_sec"])
        for x in e.get("false_alerts") or []:
            fa[e["scenario"]].append({"type": x["type"], "severity": x["severity"], "at_sec": x["at_sec"], "reason": x["reason"],
                                      "intensity": (e.get("params") or {}).get("intensity"), "seed": (e.get("params") or {}).get("seed")})
    res = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "elapsed_sec": round(time.time() - t0, 1), "runs": len(exps),
           "intensities": INTENSITIES, "seeds": SEEDS, "all": evaluate.aggregate(exps), "by_intensity": per_int,
           "latency": {f"{s}|{i}": {"n": len(v), "min": min(v), "median": statistics.median(v), "max": max(v)} for (s, i), v in lat.items()},
           "false_alerts": fa,
           "note": "합성 데이터 기준. 생성기와 탐지기를 같은 프로젝트에서 만들었으므로 실제 환경 성능을 보장하지 않음."}
    out.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print("saved", out, f"{res['elapsed_sec']}s")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "benchmark" / "simlab_eval.json")
