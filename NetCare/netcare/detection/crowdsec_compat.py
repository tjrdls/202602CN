"""CrowdSec 시나리오와 같은 조건을 패킷에서 판정하는 모듈.

CrowdSec 은 웹 서버·sshd·방화벽 '로그'를 읽어 leaky bucket 시나리오로 공격을 찾는다.
NetCare 는 로그 대신 패킷에서 같은 사건(event)을 만든다.

| NetCare 사건 (패킷에서 추출)                 | 대응 CrowdSec 시나리오 |
|---|---|
| 평문 HTTP 요청 경로·인자·User-Agent         | http-sensitive-files, http-path-traversal-probing, http-sqli-probing, http-xss-probing, http-backdoors-attempts, http-bad-user-agent, http-crawl-non_statics, apache_log4j2_cve-2021-44228, http-cve-2021-41773/42013 |
| 평문 HTTP 응답 코드(요청과 짝지음)          | http-probing, http-admin-interface-probing |
| FTP 응답 530(로그인 실패)                   | vsftpd-bf |
| SSH(22) 연결 시도                           | ssh-bf (sshd 로그의 '인증 실패' 대신 연결 수로 근사 → '의심') |
| 열려 있지 않은 포트로 온 SYN                | iptables-scan-multi_ports (방화벽 차단 로그 대신) |

leaky bucket 은 CrowdSec 과 같은 의미로 동작한다: capacity 개까지 담고 leakspeed 마다 1개씩 비며,
가득 찬 상태에서 새 사건이 오면 넘침(overflow) = 탐지. distinct 가 있으면 같은 값은 한 번만 센다.
패턴 목록은 CrowdSec Hub 데이터를 그대로 쓴다 (data/crowdsec, MIT).

NetCare 확장 시나리오 (CrowdSec 에 없음, evidence.netcare_extension=True 로 구분)
- URL 디코딩 후 비교: CrowdSec 패턴은 로그에 적힌 그대로(인코딩된 상태) 비교하므로 '%3Cscript%3E' 처럼 인코딩된 공격을 놓친다.
- SQL 인젝션 문법 휴리스틱: ' and 1=1, order by N, union select, 주석(--, #) 등 수동 공격 형태
- 웹 로그인 무차별 대입: 같은 로그인 경로로 POST 반복 (실패 응답이 401/403 이 아니라 302·200 인 앱도 잡음)

한계: HTTPS(443) 요청은 암호화되어 있어 HTTP 시나리오를 적용할 수 없다. 로그를 보는 CrowdSec 은 HTTPS 도 본다.
"""
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_plus

DATA = Path(__file__).resolve().parent / "data" / "crowdsec"
STATIC_EXT = {"js", "css", "png", "jpg", "jpeg", "gif", "ico", "svg", "webp", "bmp", "woff", "woff2", "ttf", "eot", "otf",
              "map", "mp4", "webm", "mp3", "wav", "pdf", "txt", "xml", "json", "avif"}


def _lines(name: str) -> list[str]:
    try:
        return [ln.strip() for ln in (DATA / name).read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []


def _regexes(name: str) -> list[re.Pattern]:
    out = []
    for ln in _lines(name):
        try:
            out.append(re.compile(ln))
        except re.error:
            continue
    return out


class Patterns:
    """CrowdSec Hub 패턴 (한 번만 읽는다)."""
    _inst = None

    def __init__(self):
        self.sensitive = _lines("sensitive_data.txt")
        self.traversal = _lines("path_traversal.txt")
        self.sqli = [p.upper() for p in _lines("sqli_probe_patterns.txt")]
        self.xss = [p.upper() for p in _lines("xss_probe_patterns.txt")]
        self.admin = [p.lower() for p in _lines("admin_interfaces.txt")]
        self.backdoors = set(_lines("backdoors.txt"))
        self.log4j = [p.upper() for p in _lines("log4j2_cve_2021_44228.txt")]
        self.bad_ua = _regexes("bad_user_agents.regex.txt")

    @classmethod
    def get(cls) -> "Patterns":
        if cls._inst is None:
            cls._inst = Patterns()
        return cls._inst


@dataclass(frozen=True)
class Scenario:
    key: str            # NetCare 내부 이름
    crowdsec: str       # 대응 CrowdSec 시나리오
    atype: str          # 알림 유형 (web_attack / web_scan / auth_bruteforce / port_scan)
    label: str
    capacity: int       # trigger 형은 0
    leak: float         # 초
    blackhole: float    # 초
    severity: str
    certainty: str = "measured"


SCENARIOS = {s.key: s for s in [
    Scenario("http_probing", "crowdsecurity/http-probing", "web_scan", "HTTP 경로 탐색(404·403·400 반복)", 10, 10, 300, "warning"),
    Scenario("http_crawl", "crowdsecurity/http-crawl-non_statics", "web_scan", "공격적인 크롤링", 40, 0.5, 60, "info"),
    Scenario("http_bad_ua", "crowdsecurity/http-bad-user-agent", "web_scan", "공격 도구 User-Agent", 1, 60, 120, "warning"),
    Scenario("http_sensitive_files", "crowdsecurity/http-sensitive-files", "web_attack", "민감한 파일 접근 시도", 4, 5, 300, "warning"),
    Scenario("http_path_traversal", "crowdsecurity/http-path-traversal-probing", "web_attack", "경로 조작(Path Traversal) 시도", 3, 10, 120, "warning"),
    Scenario("http_sqli", "crowdsecurity/http-sqli-probbing-detection", "web_attack", "SQL 인젝션 시도", 10, 1, 300, "danger"),
    Scenario("http_xss", "crowdsecurity/http-xss-probbing", "web_attack", "XSS 시도", 5, 1, 300, "warning"),
    Scenario("http_admin_probing", "crowdsecurity/http-admin-interface-probing", "web_attack", "관리자 페이지 탐색", 2, 10, 300, "warning"),
    Scenario("http_backdoor", "crowdsecurity/http-backdoors-attempts", "web_attack", "웹 백도어 접근 시도", 1, 5, 300, "danger"),
    Scenario("http_log4j", "crowdsecurity/apache_log4j2_cve-2021-44228", "web_attack", "Log4Shell(CVE-2021-44228) 공격 시도", 0, 0, 300, "danger"),
    Scenario("http_cve_41773", "crowdsecurity/http-cve-2021-41773", "web_attack", "Apache 경로 조작(CVE-2021-41773) 시도", 0, 0, 300, "danger"),
    Scenario("http_cve_42013", "crowdsecurity/http-cve-2021-42013", "web_attack", "Apache 경로 조작(CVE-2021-42013) 시도", 0, 0, 300, "danger"),
    Scenario("ftp_bf", "crowdsecurity/vsftpd-bf", "auth_bruteforce", "FTP 로그인 무차별 대입", 5, 10, 60, "warning"),
    Scenario("ssh_bf", "crowdsecurity/ssh-bf", "auth_bruteforce", "SSH 로그인 무차별 대입", 5, 10, 60, "warning", "suspected"),
    Scenario("scan_multi_ports", "crowdsecurity/iptables-scan-multi_ports", "port_scan", "여러 포트 탐색", 15, 5, 60, "warning"),
    # ── NetCare 확장 (CrowdSec 에 없는 조건) ──
    Scenario("ext_xss_decoded", "", "web_attack", "XSS 시도 (URL 디코딩 후 탐지)", 5, 10, 300, "warning"),
    Scenario("ext_sqli", "", "web_attack", "SQL 인젝션 시도 (문법 휴리스틱·디코딩 후 탐지)", 2, 30, 300, "danger"),
    Scenario("ext_traversal_decoded", "", "web_attack", "경로 조작 시도 (URL 디코딩 후 탐지)", 3, 10, 120, "warning"),
    Scenario("ext_http_login_bf", "", "auth_bruteforce", "웹 로그인 무차별 대입 (같은 로그인 경로 POST 반복)", 10, 10, 120, "warning", "likely"),
]}

SQLI_RX = re.compile(
    r"""['"`)]\s*(and|or|&&|\|\|)\s+['"\w]*\s*(=|<|>|like)\s*['"\w]*"""   # ' and 1=1 / ' or 'a'='a
    r"""|['"`)]\s*(and|or)\s+\d+\s*(=|<|>)"""                       # ' and 1>0
    r"""|\border\s+by\s+\d+"""                                      # order by 3
    r"""|\bunion(\s+all)?\s+select\b"""
    r"""|['"`]\s*(--|#|/\*)"""                                        # 따옴표 뒤 주석
    r"""|\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\("""
    r"""|\binformation_schema\b|\bxp_cmdshell\b|@@version""", re.I)
LOGIN_RX = re.compile(r"(log[_-]?in|sign[_-]?in|logon|auth|session|wp-login|account)", re.I)


def _decode(x: str) -> str:
    """URL 인코딩을 두 번까지 푼다 (이중 인코딩 우회 대응)."""
    try:
        once = unquote_plus(x)
        return unquote_plus(once) if "%" in once else once
    except Exception:
        return x


class Bucket:
    """CrowdSec leaky bucket (Go rate.Limiter burst=capacity, rate=1/leak 와 같은 동작)."""
    __slots__ = ("tokens", "last", "recent", "events", "overflow_at", "blackhole_until", "last_event", "samples")

    def __init__(self, capacity: int, now: float):
        self.tokens = float(capacity)
        self.last = now
        self.recent: deque = deque(maxlen=max(capacity, 1))   # distinct 판정용 (통 안에 있는 값)
        self.events = 0
        self.overflow_at = None
        self.blackhole_until = 0.0
        self.last_event = now
        self.samples: list = []

    def pour(self, sc: Scenario, now: float, value) -> bool:
        """사건 1개를 붓는다. 넘치면 True."""
        self.last_event = now
        if sc.capacity == 0:          # trigger 형
            hit = now >= self.blackhole_until
        else:
            self.tokens = min(sc.capacity, self.tokens + (now - self.last) / sc.leak)
            self.last = now
            if value is not None and value in self.recent:
                return False
            if value is not None:
                self.recent.append(value)
            self.events += 1
            if len(self.samples) < 8 and value is not None:
                self.samples.append(str(value)[:120])
            if self.tokens >= 1:
                self.tokens -= 1
                return False
            hit = now >= self.blackhole_until
        if hit:
            self.overflow_at = now
            self.blackhole_until = now + sc.blackhole
        return hit


def _split(uri: str) -> tuple[str, str, str]:
    path, _, args = uri.partition("?")
    fname = path.rsplit("/", 1)[-1]
    return path, args, fname


class CompatDetector:
    MAX_BUCKETS = 20000

    def __init__(self, det):
        self.det = det
        self.p = Patterns.get()
        self.buckets: dict[tuple, Bucket] = {}
        self.pending: dict[tuple, deque] = {}       # HTTP 흐름 → 응답을 기다리는 요청
        self.open_ports: dict[tuple, float] = {}    # (ip, port) → 마지막 SYN-ACK 시각 (열린 포트)
        self.hits: dict[tuple, dict] = {}           # (scenario, src, dst) → 최근 넘침 정보

    # ───────────── 사건 ─────────────
    def _event(self, key: str, src: str, dst: str | None, port, now: float, value=None, match: str | None = None):
        sc = SCENARIOS[key]
        group = (key, src, dst if key in ("http_probing", "http_crawl") else None)
        b = self.buckets.get(group)
        if b is None:
            if len(self.buckets) >= self.MAX_BUCKETS:
                return
            b = self.buckets[group] = Bucket(sc.capacity, now)
        if b.pour(sc, now, value):
            h = self.hits.setdefault((key, src, dst), {"first": now, "count": 0, "matches": []})
            h.update(last=now, port=port, events=b.events, samples=list(b.samples))
            h["count"] += 1
            if match and len(h["matches"]) < 5 and match not in h["matches"]:
                h["matches"].append(match)
        elif (key, src, dst) in self.hits:
            self.hits[(key, src, dst)]["last"] = now   # 공격이 이어지는 동안 알림 유지

    def observe(self, r: dict):
        now = r.get("ts") or time.time()
        proto, src, dst = r.get("proto"), r.get("src"), r.get("dst")
        if proto != "TCP" or not src:
            return
        fl = r.get("flags") or ""
        if "S" in fl and "A" in fl:
            self.open_ports[(src, r.get("sport"))] = now
        elif "S" in fl and "A" not in fl and "R" not in fl:
            dport = r.get("dport")
            if dport == 22:
                self._event("ssh_bf", src, dst, 22, now)
            if now - self.open_ports.get((dst, dport), -1e9) > 120:
                self._event("scan_multi_ports", src, dst, None, now, value=dport)
        if r.get("ftp_code") == 530:
            self._event("ftp_bf", dst, src, 21, now)
        h = r.get("http")
        if not h:
            return
        if h["kind"] == "req":
            self._http_request(r, h, now)
        else:
            q = self.pending.get((dst, r.get("dport"), src, r.get("sport")))
            if q:
                self._http_response(q.popleft(), h["status"], now)

    def _http_request(self, r: dict, h: dict, now: float):
        src, dst, sport, dport = r["src"], r["dst"], r.get("sport"), r.get("dport")
        uri = h["uri"]
        path, args, fname = _split(uri)
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        static = ext in STATIC_EXT
        req = {"uri": uri, "path": uri, "fname": fname, "static": static, "method": h["method"], "src": src, "dst": dst, "port": dport, "ts": now}
        flow = (src, sport, dst, dport)
        q = self.pending.get(flow)
        if q is None:
            if len(self.pending) > 20000:
                self.pending.clear()
            q = self.pending[flow] = deque(maxlen=32)
        q.append(req)
        p = self.p
        # CrowdSec 은 로그에 적힌 그대로(URL 인코딩된 상태)의 요청 문자열에 패턴을 대므로 디코딩하지 않는다.
        # http_path(=요청 대상 전체, 쿼리 포함)와 http_args(쿼리) 를 그대로 쓴다.
        up_uri, up_args = uri.upper(), args.upper()
        if any(uri.endswith(x) or path.endswith(x) for x in p.sensitive):
            self._event("http_sensitive_files", src, dst, dport, now, value=uri, match=uri)
        tv = next((t for t in p.traversal if t in uri), None)
        if tv:
            self._event("http_path_traversal", src, dst, dport, now, value=uri, match=tv)
        if args:
            m = next((x for x in p.sqli if x in up_args), None)
            if m:
                self._event("http_sqli", src, dst, dport, now, value=args, match=m)
            m = next((x for x in p.xss if x in up_args), None)
            if m:
                self._event("http_xss", src, dst, dport, now, value=args, match=m)
        if fname and fname in p.backdoors:
            self._event("http_backdoor", src, dst, dport, now, value=fname, match=fname)
        ua_up, ref_up = h.get("ua", "").upper(), h.get("referer", "").upper()
        m = next((x for x in p.log4j if x in up_uri or x in ua_up or x in ref_up), None)
        if m:
            self._event("http_log4j", src, dst, dport, now, match=m)
        if "/.%2E/.%2E/" in up_uri or "/%2E%2E/%2E%2E" in up_uri:
            self._event("http_cve_41773", src, dst, dport, now, match=path)
        if "/%%32%65%%32%65/" in up_uri:
            self._event("http_cve_42013", src, dst, dport, now, match=path)
        # ── NetCare 확장: 디코딩 후 비교 · SQL 문법 · 로그인 반복 ──
        dec_args = _decode(args) if args else ""
        dec_uri = _decode(uri)
        if dec_args and dec_args != args:
            up_dec = dec_args.upper()
            m = next((x for x in p.xss if x in up_dec), None)
            if m:
                self._event("ext_xss_decoded", src, dst, dport, now, value=args, match=m)
        if dec_args:
            m = SQLI_RX.search(dec_args)
            if m:
                self._event("ext_sqli", src, dst, dport, now, value=args, match=m.group(0)[:60])
        if dec_uri != uri:
            tv = next((t for t in p.traversal if t in dec_uri and t not in uri), None)
            if tv:
                self._event("ext_traversal_decoded", src, dst, dport, now, value=uri, match=tv)
        if h["method"] == "POST" and LOGIN_RX.search(path):
            self._event("ext_http_login_bf", src, dst, dport, now)
        ua = h.get("ua", "")
        if ua:
            m = next((rx.pattern for rx in p.bad_ua if rx.search(ua)), None)
            if m:
                self._event("http_bad_ua", src, dst, dport, now, value=ua, match=ua[:80])
        if not static and h["method"] in ("GET", "HEAD"):
            self._event("http_crawl", src, dst, dport, now, value=fname or "/")

    def _http_response(self, req: dict, status: int, now: float):
        src, dst, port = req["src"], req["dst"], req["port"]
        if status in (404, 403, 400) and not req["static"]:
            self._event("http_probing", src, dst, port, now, value=req["path"])
        if status in (404, 403):
            low = req["path"].lower()
            m = next((a for a in self.p.admin if a in low), None)
            if m:
                self._event("http_admin_probing", src, dst, port, now, value=req["path"], match=m)

    # ───────────── 평가 ─────────────
    def maybe_housekeep(self, now: float):
        hk = getattr(self, "_housekeep_at", None)
        if hk is None or now - hk >= 30 or now < hk:
            self._housekeep_at = now
            self.housekeep(now)

    def housekeep(self, now: float):
        """장시간 실행 정리: 다 비워진(새로 만든 것과 같은) 통과 오래된 열린 포트 기록을 지운다.

        CrowdSec 도 통이 완전히 비면(underflow) 그 통을 없앤다. 다 빈 통을 지워도 판정 결과는 같다.
        """
        def drained(key, b):
            sc = SCENARIOS[key[0]]
            return now >= b.blackhole_until and now - b.last_event >= max(sc.capacity, 1) * sc.leak
        self.buckets = {k: b for k, b in self.buckets.items() if not drained(k, b)}
        self.open_ports = {k: v for k, v in self.open_ports.items() if now - v < 300}    # 규칙은 120초 이내만 봄
        self.pending = {k: q for k, q in self.pending.items() if q and now - q[-1].get("ts", now) < 60}   # 60초 넘게 응답 없는 요청 흐름
        for k in [k for k, h in self.hits.items() if now - h["last"] > 600]:
            del self.hits[k]

    def evaluate(self, now: float, W: int) -> list[dict]:
        self.maybe_housekeep(now)
        if len(self.open_ports) > 50000:
            self.open_ports = {k: v for k, v in self.open_ports.items() if now - v < 300}
        if len(self.buckets) > self.MAX_BUCKETS * 0.8:
            self.buckets = {k: b for k, b in self.buckets.items() if now - b.last_event < 600}
        out = []
        for (key, src, dst), h in list(self.hits.items()):
            if now - h["last"] > max(W, 10):
                if now - h["last"] > 600:
                    del self.hits[(key, src, dst)]
                continue
            sc = SCENARIOS[key]
            cond = (f"단일 사건으로 탐지 (trigger)" if sc.capacity == 0 else
                    f"leaky bucket: 용량 {sc.capacity}, {sc.leak:g}초마다 1개씩 비움 → 넘치면 탐지")
            origin = f"CrowdSec {sc.crowdsec} 와 같은 조건" if sc.crowdsec else "NetCare 확장 (CrowdSec 에 없는 조건)"
            out.append(dict(type=sc.atype, severity=sc.severity, src=src, dst=dst, port=h.get("port"),
                            protocol="TCP", criterion=f"{sc.label} · {origin} ({cond})",
                            threshold=sc.capacity, measured=h.get("events") or 1,
                            evidence={"scenario": key, "scenario_label": sc.label, "crowdsec": sc.crowdsec or None,
                                      "netcare_extension": not sc.crowdsec,
                                      "certainty": sc.certainty, "overflows": h["count"], "events": h.get("events"),
                                      "matches": h["matches"], "samples": h.get("samples", [])[:5],
                                      "first_seen": h["first"], "method": "leaky bucket"}))
            if key == "scan_multi_ports":   # 기존 포트 스캔 설명과 같은 근거 필드
                out[-1]["evidence"].update(window_sec=W, distinct_targets=h.get("events"), distinct_hosts=1, distinct_ports=h.get("events"),
                                           pattern="닫힌 포트 여러 곳 (CrowdSec 방식)", sample_ports=h.get("samples", [])[:15])
        return out
