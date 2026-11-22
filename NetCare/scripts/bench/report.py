"""CSE-CIC-IDS2018 벤치마크 결과 비교표 생성 (NetCare vs CrowdSec).

입력: <in>/<case>/netcare_result.json (cse_cic_ids2018.py), <in>/<case>/crowdsec_alerts.json (cscli alerts list -o json)
출력: <out>/cse-cic-ids2018.md, <out>/cse-cic-ids2018.json

판정 방법
- 라벨 CSV 시각은 오전/오후 표시 없는 12시간제라 01~06시를 오후로 고친 뒤(fix_12h),
  pcap 의 새 연결(SYN) 분포와 맞춰 시간대 차이(시간 단위)를 자동 계산한다.
- 공격 구간 = 그 라벨의 첫 분 ~ 마지막 분 (+60초). 공격자 = 그 구간에 해당 포트로 새 연결을 가장 많이 만든 외부 주소.
- 탐지 = 공격자 주소가 출발지이고, 구간(앞뒤 2분 여유)과 겹치고, 공격 종류에 맞는 유형의 알림.
- 라벨 밖 탐지 = 어떤 공격 구간·공격자와도 맞지 않는 보안 알림 (라벨에 없는 실제 공격일 수도 있어 따로 나열).
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

SECURITY_TYPES = {"port_scan", "syn_surge", "repeated_connection", "web_attack", "web_scan", "auth_bruteforce", "ip_spoof_suspect",
                  "arp_spoof", "dns_spoof_suspect", "tcp_injection", "udp_replay", "checksum_error", "ip_packet_flood"}
FAMILY = {"ftp": {"port": 21, "netcare": {"auth_bruteforce"}, "crowdsec": ("crowdsecurity/vsftpd",)},
          "ssh": {"port": 22, "netcare": {"auth_bruteforce"}, "crowdsec": ("crowdsecurity/ssh",)},
          "web": {"port": 80, "netcare": {"web_attack", "web_scan", "auth_bruteforce"}, "crowdsec": ("crowdsecurity/http", "crowdsecurity/apache")}}
PAD = 120


def keywords(label: str) -> tuple[str, ...]:
    """공격 종류별로 '맞는 탐지'로 인정할 시나리오 이름 조각."""
    low = label.lower()
    if "xss" in low:
        return ("xss",)
    if "sql" in low:
        return ("sqli",)
    if "ftp" in low:
        return ("ftp_bf", "vsftpd")
    if "ssh" in low:
        return ("ssh_bf", "ssh-")
    return ("login_bf", "-bf", "_bf")          # 웹 로그인 무차별 대입


def family(label: str) -> str | None:
    low = label.lower()
    if "ftp" in low:
        return "ftp"
    if "ssh" in low:
        return "ssh"
    if any(k in low for k in ("web", "xss", "sql")):
        return "web"
    return None


def _minute(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)


def fix_12h(minutes: dict) -> dict:
    """CSE-CIC-IDS2018 라벨 CSV 의 시각은 오전/오후 표시 없는 12시간제다 (예: 오후 1:51 → '01:51').
    실험은 현지 근무 시간(약 08~18시)에 진행됐으므로 01~06시는 오후(+12시간)로 본다."""
    out = {}
    for k, v in minutes.items():
        port, m = k.split("|", 1)
        t = _minute(m)
        if 1 <= t.hour <= 6:
            t += timedelta(hours=12)
        key = f"{port}|{t.strftime('%Y-%m-%d %H:%M')}"
        out[key] = out.get(key, 0) + v
    return out


def estimate_offset(label_minutes: dict, syn_minutes: dict, port: int) -> int:
    """라벨 시각 + offset(시간) = UTC 가 되는 offset 을 고른다."""
    syn = {k.split("|", 1)[1] for k, v in syn_minutes.items() if k.startswith(f"{port}|") and v}
    lab = [k.split("|", 1)[1] for k in label_minutes if k.startswith(f"{port}|")]
    best, score = 0, -1
    for h in range(-14, 15):
        sc = sum(1 for m in lab if (_minute(m) + timedelta(hours=h)).strftime("%Y-%m-%d %H:%M") in syn)
        if sc > score:
            best, score = h, sc
    return best


def parse_ts(x) -> float | None:
    if x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x)
    s = str(x).replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S %z %Z"):
        try:
            return (datetime.fromisoformat(s) if fmt is None else datetime.strptime(str(x), fmt)).timestamp()
        except ValueError:
            continue
    return None


def load_crowdsec(path: Path) -> list[dict] | None:
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw or raw == "null":
        return []
    data = json.loads(raw)
    items = data if isinstance(data, list) else data.get("alerts", [])
    out = []
    for a in items:
        src = (a.get("source") or {}).get("ip") or (a.get("source") or {}).get("value")
        out.append({"scenario": a.get("scenario", ""), "src": src, "start": parse_ts(a.get("start_at")),
                    "end": parse_ts(a.get("stop_at")) or parse_ts(a.get("start_at")), "events": a.get("events_count")})
    return out


def evaluate_case(res: dict, cs: list[dict] | None) -> dict:
    nc = res["netcare"]
    labels = res.get("labels") or {}
    attacks = []
    labels = dict(labels, minutes={lab: fix_12h(m) for lab, m in (labels.get("minutes") or {}).items()})
    # 같은 날의 라벨은 같은 시계를 쓰므로 시간대 차이는 하루에 하나: 모든 공격 라벨을 합쳐 추정
    allmins = {}
    for lab, minutes in (labels.get("minutes") or {}).items():
        if family(lab):
            allmins.update({k: v for k, v in minutes.items() if k.startswith(f"{FAMILY[family(lab)]['port']}|")})
    ports = {int(k.split("|", 1)[0]) for k in allmins}
    off = max(range(-14, 15), key=lambda h: sum(
        sum(1 for k in allmins if k.startswith(f"{p}|") and
            (_minute(k.split("|", 1)[1]) + timedelta(hours=h)).strftime("%Y-%m-%d %H:%M") in
            {m.split("|", 1)[1] for m, v in nc["syn_minutes"].items() if m.startswith(f"{p}|") and v}) for p in ports)) if allmins else 0
    for lab, minutes in (labels.get("minutes") or {}).items():
        fam = family(lab)
        if fam is None:
            continue
        port = FAMILY[fam]["port"]
        mins = {k: v for k, v in minutes.items() if k.startswith(f"{port}|")}
        if not mins:
            continue
        times = sorted(_minute(k.split("|", 1)[1]) + timedelta(hours=off) for k in mins)
        start, end = times[0].timestamp(), times[-1].timestamp() + 60
        srcs = Counter()
        for k, v in nc["syn_minutes"].items():
            p, m = k.split("|", 1)
            if int(p) == port and start <= _minute(m).timestamp() < end:
                srcs.update(v)
        attacker = srcs.most_common(1)[0][0] if srcs else None
        attacks.append({"label": lab, "family": fam, "port": port, "flows": labels["totals"].get(lab), "offset_h": off,
                        "start": start, "end": end, "attacker": attacker})

    def match(items, fam_key, kind):
        res_ = {}
        for at in attacks:
            fam = FAMILY[at["family"]]
            hits = []
            for it in items:
                if it.get("src") != at["attacker"] or it["start"] is None:
                    continue
                if it["end"] < at["start"] - PAD or it["start"] > at["end"] + PAD:
                    continue
                kws = keywords(at["label"])
                name = (it.get("scenario") or it.get("type") or "").lower()
                ok = ((it["type"] in fam["netcare"]) if kind == "netcare" else it["scenario"].startswith(fam["crowdsec"])) and any(k in name for k in kws)
                if ok:
                    hits.append(it)
            res_[at["label"]] = hits
        return res_

    nc_items = [i for i in nc["incidents"]]
    nc_hits = match(nc_items, "netcare", "netcare")
    cs_hits = match(cs or [], "crowdsec", "crowdsec") if cs is not None else None
    used_nc = {id(i) for v in nc_hits.values() for i in v}
    rows = []
    for at in attacks:
        h = sorted(nc_hits[at["label"]], key=lambda x: x["start"])
        row = {**at, "netcare_detected": bool(h), "netcare_latency_sec": round(max(0, h[0]["start"] - at["start"]), 1) if h else None,
               "netcare_scenarios": sorted({i["scenario"] or i["type"] for i in h}),
               "netcare_via_extension": bool(h) and all((i["scenario"] or "").startswith("ext_") for i in h)}
        if at["family"] == "ssh":
            row.update(crowdsec_detected=None, crowdsec_note="sshd 로그 필요 (패킷으로 만들 수 없음) → 측정 불가")
        elif cs_hits is None:
            row.update(crowdsec_detected=None, crowdsec_note="CrowdSec 결과 없음")
        else:
            c = sorted(cs_hits[at["label"]], key=lambda x: x["start"])
            row.update(crowdsec_detected=bool(c), crowdsec_latency_sec=round(max(0, c[0]["start"] - at["start"]), 1) if c else None,
                       crowdsec_scenarios=sorted({i["scenario"] for i in c}))
        rows.append(row)
    attackers = {a["attacker"] for a in attacks}
    nc_extra = [i for i in nc_items if id(i) not in used_nc and i["type"] in SECURITY_TYPES and i.get("src") not in attackers]
    nc_other = Counter(i["type"] for i in nc_items if i["type"] not in SECURITY_TYPES)
    cs_extra = [i for i in (cs or []) if i["src"] not in attackers] if cs is not None else None
    hours = max(1e-9, ((nc["last_ts"] or 0) - (nc["first_ts"] or 0)) / 3600)
    return {"case": res["case"], "packets": nc["packets"], "capture_hours": round(hours, 2), "attacks": rows,
            "netcare_unlabeled": nc_extra, "netcare_nonsecurity": dict(nc_other), "crowdsec_unlabeled": cs_extra,
            "crowdsec_alerts": len(cs) if cs is not None else None, "log_counts": nc.get("log_counts"), "diag": nc.get("diag")}


def fmt_t(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M") if ts else "-"


def mark(v):
    return "✅" if v else ("❌" if v is False else "—")


def render(cases: list[dict]) -> str:
    out = ["# 공개 데이터셋 벤치마크: CSE-CIC-IDS2018 — NetCare vs CrowdSec", "",
           "같은 패킷을 두 도구에 넣어 비교했습니다. NetCare는 pcap을 그대로 분석하고, CrowdSec은 같은 패킷에서 만든 웹 서버(Apache) 접근 로그와 vsftpd 로그를 읽습니다(실제 CrowdSec을 GitHub Actions에서 time-machine 모드로 실행).", "",
           "- 데이터: [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) (CIC·CSE, AWS 공개 버킷), 공격받은 서버의 호스트 캡처만 사용",
           "- 정답: 같은 데이터셋의 CICFlowMeter 라벨 CSV. 라벨 시각은 오전/오후 표시가 없는 12시간제라 01~06시를 오후로 고치고, pcap의 새 연결 분포와 맞춰 시간대를 정한 뒤 공격 구간·공격자 주소를 정했습니다.",
           "- NetCare 탐지 중 `ext_`로 시작하는 시나리오는 CrowdSec에 없는 NetCare 확장 조건(URL 디코딩 후 비교, SQL 문법, 로그인 반복)입니다.",
           "- SSH는 암호화되어 sshd 인증 실패 로그를 패킷으로 만들 수 없으므로 CrowdSec은 '측정 불가'입니다(실제 서버에서는 sshd 로그로 탐지 가능).", ""]
    out += ["| 사례 | 공격(라벨) | 공격 구간(UTC) | 공격자 | NetCare | 소요 | NetCare 시나리오 | CrowdSec | 소요 | CrowdSec 시나리오 |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for c in cases:
        for r in c["attacks"]:
            cs_s = ", ".join(r.get("crowdsec_scenarios") or []) or r.get("crowdsec_note", "-")
            out.append(f"| {c['case']['day']} | {r['label']} ({r['flows']:,}흐름) | {fmt_t(r['start'])}–{fmt_t(r['end'])} | {r['attacker']} | "
                       f"{mark(r['netcare_detected'])} | {r['netcare_latency_sec'] if r['netcare_latency_sec'] is not None else '-'}초 | "
                       f"{', '.join(r['netcare_scenarios']) or '-'} | {mark(r.get('crowdsec_detected'))} | "
                       f"{r.get('crowdsec_latency_sec') if r.get('crowdsec_latency_sec') is not None else '-'}초 | {cs_s} |")
    out += ["", "## 라벨 밖 탐지 (공격 구간·공격자와 맞지 않는 보안 알림)", "",
            "라벨은 실험자가 낸 공격만 표시합니다. 인터넷에 열린 실험 서버라 실제 외부 스캐너·무차별 대입이 섞여 있으므로, 아래가 모두 오탐인 것은 아닙니다.", ""]
    for c in cases:
        ne = c["netcare_unlabeled"]
        cs = c["crowdsec_unlabeled"]
        out.append(f"- **{c['case']['day']}** (캡처 {c['capture_hours']}시간, 패킷 {c['packets']:,}개): "
                   f"NetCare {len(ne)}건" + (f" ({', '.join(sorted({(i['scenario'] or i['type']) + ' ' + str(i['src']) for i in ne}))[:300]})" if ne else "")
                   + (f" · CrowdSec {len(cs)}건" + (f" ({', '.join(sorted({i['scenario'] + ' ' + str(i['src']) for i in cs}))[:300]})" if cs else "") if cs is not None else "")
                   + (f" · NetCare 비보안 알림(품질·사용량): {c['netcare_nonsecurity']}" if c["netcare_nonsecurity"] else ""))
    diags = [c for c in cases if (c.get("diag") or {}).get("ftp_server_flags") or (c.get("diag") or {}).get("ftp_client_flags")]
    if diags:
        out += ["", "## 진단: FTP 서버 응답", ""]
        for c in diags:
            d = c["diag"]
            out.append(f"- **{c['case']['day']}**: 서버→클라이언트 TCP 플래그 {d.get('ftp_server_flags')}, 클라이언트→서버 {d.get('ftp_client_flags')}, "
                       f"서버 응답 코드 {d.get('ftp_server_codes')}")
    out += ["", f"생성: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · 스크립트: `scripts/bench/cse_cic_ids2018.py`, `scripts/bench/report.py` · 워크플로: `.github/workflows/netcare-bench.yml`"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cases = []
    for d in sorted(Path(a.inp).glob("*/netcare_result.json")):
        res = json.loads(d.read_text(encoding="utf-8"))
        cs = load_crowdsec(d.parent / "crowdsec_alerts.json")
        cases.append(evaluate_case(res, cs))
    order = {"ftp_ssh": 0, "web_thu": 1, "web_fri": 2}
    cases.sort(key=lambda c: order.get(c["case"]["name"], 9))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cse-cic-ids2018.json").write_text(json.dumps(cases, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "cse-cic-ids2018.md").write_text(render(cases), encoding="utf-8")
    print(render(cases))


if __name__ == "__main__":
    main()
