"""DoT(DNS over TLS, RFC 7858) 기본 기능 실측 — 공개 리졸버에 평범한 DNS 조회를 TLS(853)로 보내고,
실행 중인 NetCare 가 그 흐름을 어떻게 분류했는지 확인한다.

    python scripts/dot_check.py --base http://127.0.0.1:8774 [--names example.com,wikipedia.org]

보내는 것: 공개 리졸버(1.1.1.1 · 8.8.8.8 · 9.9.9.9)로의 일반 DNS 질의(A 레코드)뿐이다. 공격 트래픽 아님.
확인하는 것:
- 실제 DoT 응답을 받았는지 (TLS 핸드셰이크 + DNS 응답 코드·주소)
- NetCare /api/encrypted 의 DNS 흐름 목록에서 해당 서버가 kind=dot · status=confirmed(확인됨) 인지
- 같은 흐름이 DoH·일반 DNS 로 잘못 분류되지 않았는지
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import ssl
import struct
import time
import urllib.request

RESOLVERS = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google"), ("9.9.9.9", "dns.quad9.net")]


def query(name: str) -> tuple[int, bytes]:
    qid = random.randint(0, 65535)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in name.strip(".").split("."):
        q += bytes([len(part)]) + part.encode()
    return qid, q + b"\x00" + struct.pack("!HH", 1, 1)


def parse_answer(resp: bytes) -> tuple[int, int, list[str]]:
    qid, flags, qd, an = struct.unpack("!HHHH", resp[:8])
    rcode = flags & 0x0F
    i = 12
    for _ in range(qd):
        while resp[i] != 0:
            i += resp[i] + 1
        i += 5
    ips = []
    for _ in range(an):
        if resp[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while resp[i] != 0:
                i += resp[i] + 1
            i += 1
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", resp[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(resp[i:i + 4]))
        i += rdlen
    return qid, rcode, ips


def dot(ip: str, host: str, names: list[str]) -> dict:
    ctx = ssl.create_default_context()
    t0 = time.time()
    with socket.create_connection((ip, 853), timeout=8) as raw:
        lport = raw.getsockname()[1]
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            out = {"server": ip, "sni": host, "local_port": lport, "tls": s.version(), "alpn": s.selected_alpn_protocol(), "answers": {}}
            for n in names:
                qid, q = query(n)
                s.sendall(struct.pack("!H", len(q)) + q)
                ln = struct.unpack("!H", s.recv(2))[0]
                buf = b""
                while len(buf) < ln:
                    buf += s.recv(ln - len(buf))
                rid, rcode, ips = parse_answer(buf)
                out["answers"][n] = {"id_match": rid == qid, "rcode": rcode, "a": ips}
    out["ms"] = round((time.time() - t0) * 1000)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8774")
    ap.add_argument("--names", default="example.com,wikipedia.org")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    names = a.names.split(",")
    results = []
    for ip, host in RESOLVERS:
        try:
            results.append(dot(ip, host, names))
        except Exception as e:
            results.append({"server": ip, "sni": host, "error": f"{type(e).__name__}: {e}"})
        print(json.dumps(results[-1], ensure_ascii=False))
    time.sleep(4)                                   # NetCare 처리·평가 대기
    with urllib.request.urlopen(a.base + "/api/encrypted", timeout=10) as r:
        enc = json.loads(r.read())
    dns = enc.get("summary", {}).get("dns") or enc.get("dns") or {}
    flows = dns.get("list") or []
    verdict = []
    for res in results:
        mine = [f for f in flows if f.get("server") == res["server"]]
        kinds = sorted({(f.get("kind"), f.get("status")) for f in mine})
        ok = bool(mine) and all(k == "dot" for k, _ in kinds) and any(s == "confirmed" for _, s in kinds)
        verdict.append({"server": res["server"], "dot_ok": "error" not in res, "netcare": kinds,
                        "basis": [f.get("basis") for f in mine][:2], "pass": ok and "error" not in res})
        print("NetCare:", json.dumps(verdict[-1], ensure_ascii=False))
    summary = {"dns_flows": dns.get("flows"), "confirmed_flows": dns.get("confirmed_flows")}
    print("DNS 요약:", json.dumps(summary, ensure_ascii=False))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({"queries": results, "netcare": verdict, "summary": summary}, f, ensure_ascii=False, indent=1)
    raise SystemExit(0 if all(v["pass"] for v in verdict) else 1)


if __name__ == "__main__":
    main()
