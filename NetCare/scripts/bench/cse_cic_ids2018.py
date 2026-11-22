"""공개 라벨 데이터셋(CSE-CIC-IDS2018)으로 NetCare 를 평가하고, 같은 패킷에서 CrowdSec 입력 로그를 만든다.

데이터: 캐나다 사이버보안연구소(CIC)·CSE 가 AWS 공개 버킷에 올린 CSE-CIC-IDS2018
  https://www.unb.ca/cic/datasets/ids-2018.html , s3://cse-cic-ids2018 (인증 없이 공개)
- 날마다 pcap.zip(약 38GB) 안에 장치별 캡처가 들어 있다. HTTP Range 로 '공격받은 서버'의 캡처만 받는다.
- 라벨은 'Processed Traffic Data for ML Algorithms' 의 CICFlowMeter CSV (흐름별 Label, Timestamp, Dst Port).

이 스크립트가 하는 일 (사례 하나당)
1. 공격받은 서버의 pcap 만 내려받기
2. 라벨 CSV 를 내려받아 공격 종류별 시간 구간(분 단위) 집계
3. pcap 을 NetCare 탐지기에 그대로 흘려 넣어 알림 수집 (실제 엔진과 같은 parse_packet → Detector)
4. 같은 패킷에서 CrowdSec 이 읽을 로그 생성: Apache combined access log, vsftpd 로그
   (SSH 는 암호화되어 sshd '인증 실패' 로그를 패킷으로 만들 수 없으므로 만들지 않는다 → CrowdSec 측정 불가로 표시)
5. 결과 JSON 저장 (report.py 가 CrowdSec 결과와 합쳐 비교표를 만든다)

    python scripts/bench/cse_cic_ids2018.py --case web_thu --out bench-out
    python scripts/bench/cse_cic_ids2018.py --case web_thu --out bench-out --no-labels   # 라벨 없이 빠르게(개발용)
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

BASE = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
CASES = {
    "ftp_ssh": {"day": "Wednesday-14-02-2018", "host": "172.31.69.25", "csv": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"},
    "web_thu": {"day": "Thursday-22-02-2018", "host": "172.31.69.28", "csv": "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"},
    "web_fri": {"day": "Friday-23-02-2018", "host": "172.31.69.28", "csv": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"},
}
LOCAL_PREFIX = "172.31."          # 실험망 내부 대역 (외부 공격자는 18.x 등 공인 주소)


def url(path: str) -> str:
    return BASE + urllib.parse.quote(path)


def fetch_pcap(case: dict, out: Path) -> Path:
    from remotezip import RemoteZip
    member = f"pcap/UCAP{case['host']}"
    dest = out / f"{case['day']}_{case['host']}.pcap"
    if dest.exists():
        return dest
    t0 = time.time()
    with RemoteZip(url(f"Original Network Traffic and Log data/{case['day']}/pcap.zip")) as z:
        with z.open(member) as src, open(dest, "wb") as f:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
    print(f"[pcap] {member} {dest.stat().st_size / 1e6:.1f}MB in {time.time() - t0:.0f}s", flush=True)
    return dest


def fetch_labels(case: dict) -> dict:
    """라벨 CSV 를 스트리밍으로 읽어 공격 종류별 (Dst Port, 분) 단위 흐름 수를 센다."""
    t0 = time.time()
    resp = urllib.request.urlopen(url(f"Processed Traffic Data for ML Algorithms/{case['csv']}"), timeout=120)
    rd = csv.reader(io.TextIOWrapper(resp, encoding="utf-8", errors="replace"))
    hdr = next(rd)
    i_port, i_ts, i_lab = hdr.index("Dst Port"), hdr.index("Timestamp"), hdr.index("Label")
    per = defaultdict(Counter)        # label → {(port, "YYYY-mm-dd HH:MM"): n}
    total = Counter()
    for row in rd:
        if len(row) <= i_lab or row[i_lab] == "Label":
            continue
        lab = row[i_lab].strip()
        total[lab] += 1
        if lab.lower() == "benign":
            continue
        try:
            dt = datetime.strptime(row[i_ts], "%d/%m/%Y %H:%M:%S")
        except ValueError:
            continue
        per[lab][(int(row[i_port]), dt.strftime("%Y-%m-%d %H:%M"))] += 1
    print(f"[labels] {sum(total.values())} flows, {dict(total)} in {time.time() - t0:.0f}s", flush=True)
    return {"totals": dict(total), "minutes": {lab: {f"{p}|{m}": n for (p, m), n in c.items()} for lab, c in per.items()}}


class LogWriter:
    """NetCare 가 패킷에서 읽은 HTTP·FTP 사건을 CrowdSec 이 읽는 로그 형식으로 쓴다."""

    def __init__(self, out: Path, host: str):
        self.host = host
        self.http = open(out / "apache_access.log", "w", encoding="utf-8")
        self.ftp = open(out / "vsftpd.log", "w", encoding="utf-8")
        self.pending: dict[tuple, deque] = {}
        self.counts = Counter()

    def feed(self, r: dict):
        h = r.get("http")
        if h and h["kind"] == "req" and r["dst"] == self.host:
            q = self.pending.setdefault((r["src"], r["sport"], r["dst"], r["dport"]), deque(maxlen=64))
            q.append((r["ts"], r["src"], h))
            self.counts["http_req"] += 1
        elif h and h["kind"] == "resp" and r["src"] == self.host:
            q = self.pending.get((r["dst"], r["dport"], r["src"], r["sport"]))
            if q:
                ts, client, rq = q.popleft()
                t = datetime.fromtimestamp(ts, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
                ua = rq.get("ua", "").replace('"', "%22") or "-"
                ref = rq.get("referer", "").replace('"', "%22") or "-"
                uri = rq["uri"].replace('"', "%22").replace(" ", "%20")
                self.http.write(f'{client} - - [{t}] "{rq["method"]} {uri} HTTP/1.1" {h["status"]} 0 "{ref}" "{ua}"\n')
                self.counts["http_logged"] += 1
        if r.get("ftp_code") == 530 and r["src"] == self.host:
            t = datetime.fromtimestamp(r["ts"], timezone.utc)
            stamp = t.strftime("%a %b ") + f"{t.day:2d}" + t.strftime(" %H:%M:%S %Y")
            self.ftp.write(f'{stamp} [pid 1000] [user] FAIL LOGIN: Client "{r["dst"]}"\n')
            self.counts["ftp_fail"] += 1

    def close(self):
        self.counts["http_unpaired"] = sum(len(q) for q in self.pending.values())
        self.http.close()
        self.ftp.close()


def run_netcare(pcap: Path, case: dict, out: Path) -> dict:
    from scapy.utils import PcapReader
    from netcare.capture.parser import parse_packet
    from netcare.config import DetectionConfig
    from netcare.detection.detector import Detector

    host = case["host"]
    det = Detector(DetectionConfig(), {host}, set(), gateway_ip=None)
    logs = LogWriter(out, host)
    alerts = defaultdict(list)              # (type, src, scenario) → [초 ...]
    meta = {}
    syn_min = defaultdict(Counter)           # (dport, 분) → {외부 출발지: 새 연결 수}
    n, first, last, sec = 0, None, None, None
    t0 = time.time()
    with PcapReader(str(pcap)) as rd:
        for pkt in rd:
            r = parse_packet(pkt, {host}, set(), store_raw=False)
            ts = r["ts"]
            if not ts:
                continue
            n += 1
            first = first or ts
            last = ts
            s = int(ts)
            if sec is None:
                sec = s
            elif s > sec:
                sec = s
                for a in det.evaluate(s):
                    ev = a.get("evidence") or {}
                    k = (a["type"], a.get("src"), ev.get("scenario") or "")
                    alerts[k].append(s)
                    meta.setdefault(k, {"severity": a["severity"], "dst": a.get("dst"), "port": a.get("port"),
                                        "crowdsec": ev.get("crowdsec"), "certainty": ev.get("certainty")})
            det.observe(r)
            logs.feed(r)
            if r["proto"] == "TCP" and r["dst"] == host and (r.get("flags") or "") in ("S", "SE", "SEC") and not str(r["src"]).startswith(LOCAL_PREFIX):
                syn_min[(r["dport"], datetime.fromtimestamp(s, timezone.utc).strftime("%Y-%m-%d %H:%M"))][r["src"]] += 1
            if n % 500000 == 0:
                print(f"[netcare] {n} packets, {time.time() - t0:.0f}s", flush=True)
    logs.close()
    incidents = []
    for k, secs in alerts.items():
        start = prev = secs[0]
        for x in secs[1:] + [None]:
            if x is None or x - prev > 120:          # 2분 넘게 끊기면 다른 사건
                incidents.append({"type": k[0], "src": k[1], "scenario": k[2], "start": start, "end": prev, **meta[k]})
                if x is not None:
                    start = x
            if x is not None:
                prev = x
    print(f"[netcare] done: {n} packets, {len(incidents)} incidents, {time.time() - t0:.0f}s", flush=True)
    return {"packets": n, "first_ts": first, "last_ts": last, "elapsed_sec": round(time.time() - t0, 1),
            "incidents": sorted(incidents, key=lambda x: x["start"]), "log_counts": dict(logs.counts),
            "syn_minutes": {f"{p}|{m}": dict(c.most_common(5)) for (p, m), c in syn_min.items()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True, choices=sorted(CASES))
    ap.add_argument("--out", default="bench-out")
    ap.add_argument("--no-labels", action="store_true")
    a = ap.parse_args()
    case = dict(CASES[a.case], name=a.case)
    out = Path(a.out) / a.case
    out.mkdir(parents=True, exist_ok=True)
    pcap = fetch_pcap(case, out)
    res = {"case": case, "dataset": "CSE-CIC-IDS2018", "source": BASE, "generated_at": datetime.now(timezone.utc).isoformat()}
    res["netcare"] = run_netcare(pcap, case, out)
    if not a.no_labels:
        res["labels"] = fetch_labels(case)
    (out / "netcare_result.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[done] {out / 'netcare_result.json'}")


if __name__ == "__main__":
    main()
