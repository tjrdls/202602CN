"""연결 품질 실측 (ping, DNS 조회).

OS 의 ping 명령을 사용하므로 관리자 권한 없이 동작한다.
측정에 실패하면 실패 사실을 그대로 돌려준다 (값을 지어내지 않음).
"""
from __future__ import annotations

import concurrent.futures as cf
import platform
import re
import socket
import subprocess
import time

SYSTEM = platform.system()
_POOL = cf.ThreadPoolExecutor(max_workers=4, thread_name_prefix="netcare-dns")


def ping(target: str, count: int = 4, timeout_ms: int = 1000) -> dict:
    res = {"target": target, "sent": 0, "received": 0, "loss_pct": None, "avg_ms": None, "min_ms": None,
           "max_ms": None, "ok": False, "error": None, "measured_at": time.time()}
    if not target:
        res["error"] = "대상이 없어요"
        return res
    if SYSTEM == "Windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    elif SYSTEM == "Darwin":
        cmd = ["ping", "-c", str(count), "-W", str(timeout_ms), "-i", "0.2", target]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), "-i", "0.2", target]
    if ":" in target and SYSTEM == "Darwin":
        cmd[0] = "ping6"
        cmd = [c for c in cmd if c not in ("-W", str(timeout_ms))]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=count * (timeout_ms / 1000 + 0.5) + 5)
        out = p.stdout + p.stderr
    except FileNotFoundError:
        res["error"] = "ping 명령을 찾을 수 없어요"
        return res
    except subprocess.TimeoutExpired:
        res.update(sent=count, received=0, loss_pct=100.0, error="시간 초과")
        return res
    return parse_ping_output(out, count, res)


def parse_ping_output(out: str, count: int, res: dict | None = None) -> dict:
    res = res or {"sent": 0, "received": 0, "loss_pct": None, "avg_ms": None, "min_ms": None, "max_ms": None,
                  "ok": False, "error": None}
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if m:
        res["sent"], res["received"] = int(m.group(1)), int(m.group(2))
    else:  # Windows (영문/한글)
        m = re.search(r"(?:Sent|보냄) = (\d+), (?:Received|받음) = (\d+)", out)
        if m:
            res["sent"], res["received"] = int(m.group(1)), int(m.group(2))
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", out)  # min/avg/max
    if m:
        res["min_ms"], res["avg_ms"], res["max_ms"] = (round(float(x), 2) for x in m.groups())
    else:
        m = re.search(r"(?:Minimum|최소) = (\d+)ms, (?:Maximum|최대) = (\d+)ms, (?:Average|평균) = (\d+)ms", out)
        if m:
            res["min_ms"], res["max_ms"], res["avg_ms"] = (float(x) for x in m.groups())
    if res["sent"]:
        res["loss_pct"] = round(100.0 * (res["sent"] - res["received"]) / res["sent"], 1)
        res["ok"] = res["received"] > 0
    elif not res.get("error"):
        res["error"] = (out.strip().splitlines() or ["알 수 없는 오류"])[-1][:200]
    return res


def dns_lookup(domain: str, timeout: float = 3.0) -> dict:
    t0 = time.perf_counter()
    fut = _POOL.submit(socket.getaddrinfo, domain, 443, 0, socket.SOCK_STREAM)
    try:
        infos = fut.result(timeout=timeout)
        addrs = sorted({i[4][0] for i in infos})
        return {"domain": domain, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1), "addresses": addrs[:6]}
    except cf.TimeoutError:
        return {"domain": domain, "ok": False, "ms": None, "error": f"{timeout:g}초 안에 응답이 없어요"}
    except socket.gaierror as e:
        return {"domain": domain, "ok": False, "ms": round((time.perf_counter() - t0) * 1000, 1), "error": f"조회 실패 ({e.strerror or e})"}
    except OSError as e:
        return {"domain": domain, "ok": False, "ms": None, "error": str(e)}


def dns_test(domains: list[str]) -> dict:
    results = [dns_lookup(d) for d in domains]
    ok = [r for r in results if r["ok"]]
    return {"tested": len(results), "failed": len(results) - len(ok), "results": results,
            "avg_ms": round(sum(r["ms"] for r in ok) / len(ok), 1) if ok else None, "measured_at": time.time()}


def run_probe(gateway: str | None, external: str, domains: list[str]) -> dict:
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        f_gw = ex.submit(ping, gateway) if gateway else None
        f_ext = ex.submit(ping, external) if external else None
        f_dns = ex.submit(dns_test, domains) if domains else None
        return {
            "gateway": f_gw.result() if f_gw else {"target": None, "error": "게이트웨이를 찾지 못했어요"},
            "external": f_ext.result() if f_ext else None,
            "dns": f_dns.result() if f_dns else None,
            "measured_at": time.time(),
        }
