"""capture_stress.py 결과(JSON)가 OS 커널 통계와 맞는지 확인한다 (CI 의 실제 캡처 검증용).

    python scripts/bench/check_capture_result.py result.json --method af_packet
"""
from __future__ import annotations

import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--method", required=True)
    a = ap.parse_args()
    rows = json.load(open(a.path, encoding="utf-8"))
    ok = True
    for r in rows:
        line = (f"rate={r['rate_target']} sent={r['sent']} kernel={r['kernel_method']} recv={r['kernel_recv']} drop={r['kernel_drop']} "
                f"app_captured={r['captured_app']} app_drop={r['app_dropped']} processed={r['processed']} rss_peak={r['rss_peak_mb']}MB rcvbuf={r.get('rcvbuf')}")
        print(line)
        checks = {
            "커널 통계 방식": r["kernel_method"] == a.method,
            "커널 수신 값 있음": r["kernel_recv"] is not None and r["kernel_drop"] is not None,
            "커널 수신 ≥ 응용 수신": (r["kernel_recv"] or 0) >= r["captured_app"],
            "응용 수신 + 커널 누락 ≥ 보낸 수의 99%": r["captured_app"] + (r["kernel_drop"] or 0) >= 0.99 * r["sent"],
            "처리 + 응용 누락 = 응용 수신": r["processed"] + r["app_dropped"] == r["captured_app"],
        }
        for k, v in checks.items():
            if not v:
                ok = False
                print("  실패:", k)
    print("결과:", "통과" if ok else "실패")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
