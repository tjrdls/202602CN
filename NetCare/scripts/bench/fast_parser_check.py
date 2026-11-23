"""빠른 해석 경로(fast_record)와 Scapy 경로(parse_packet)의 결과가 같은지 실측 패킷으로 대조한다.

    python scripts/bench/fast_parser_check.py <netcare.db 또는 .pcap> [...] [--local 172.16.104.63] [--limit 0]

- 실제 엔진과 같이 scapy.all 을 불러온 상태(모든 기본 계층 바인딩)에서 비교한다.
- 빠른 경로가 처리한 패킷은 레코드의 모든 필드(_payload·raw 포함)가 같아야 한다.
- 빠른 경로가 넘긴(None) 패킷 비율과 이유별 건수, 두 경로의 패킷당 시간도 출력한다.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import scapy.all  # noqa: E402,F401  (엔진의 실시간 캡처와 같은 계층 바인딩)
from scapy.layers.l2 import Ether, Loopback  # noqa: E402

from netcare.capture.capstats import RawFrame  # noqa: E402
from netcare.capture.parser import fast_record, parse_packet  # noqa: E402


def frames(path: str, limit: int):
    if path.endswith((".pcap", ".pcapng")):
        from scapy.utils import RawPcapReader
        rd = RawPcapReader(path)
        link = "null" if rd.linktype == 0 else "ether"
        for i, (data, meta) in enumerate(rd):
            if limit and i >= limit:
                return
            yield data, meta.sec + meta.usec / 1e6, link
        return
    c = sqlite3.connect(path)
    q = "SELECT raw, ts FROM packets WHERE raw IS NOT NULL AND first_layer='Ether' ORDER BY id" + (f" LIMIT {limit}" if limit else "")
    for raw, ts in c.execute(q):
        yield bytes(raw), ts, "ether"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--local", default="172.16.104.63")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    lips = {a.local}
    total = fast = same = 0
    diffs: list = []
    skipped = Counter()
    t_fast = t_slow = 0.0
    for path in a.paths:
        for data, ts, link in frames(path, a.limit):
            total += 1
            t = time.perf_counter()
            r1 = fast_record(data, ts, lips, set(), link=link)
            t_fast += time.perf_counter() - t
            p = RawFrame(Ether if link == "ether" else Loopback, data, ts).dissect()      # 엔진과 같이: 해석 실패는 Raw
            t = time.perf_counter()
            r2 = parse_packet(p, lips, set())
            t_slow += time.perf_counter() - t
            if r1 is None:
                skipped[r2.get("proto")] += 1
                continue
            fast += 1
            if r1 == r2:
                same += 1
            elif len(diffs) < 20:
                keys = sorted(k for k in set(r1) | set(r2) if r1.get(k) != r2.get(k))
                diffs.append({"keys": keys, "fast": {k: repr(r1.get(k))[:120] for k in keys}, "scapy": {k: repr(r2.get(k))[:120] for k in keys}})
    res = {"packets": total, "fast_path": fast, "fast_ratio": round(fast / total, 4) if total else 0, "identical": same,
           "mismatch": fast - same, "fallback_by_proto": dict(skipped), "examples": diffs,
           "note": "Scapy 경로 시간에는 Scapy 해석이 빠져 있음(측정 대상 parse_packet 만)."}
    print(json.dumps({k: v for k, v in res.items() if k != "examples"}, ensure_ascii=False))
    for d in diffs[:5]:
        print(json.dumps(d, ensure_ascii=False))
    if a.out:
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    sys.exit(1 if res["mismatch"] else 0)


if __name__ == "__main__":
    main()
