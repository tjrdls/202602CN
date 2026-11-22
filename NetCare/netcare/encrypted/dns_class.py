"""일반 DNS / DoT / DoQ / DoH 분류 — '확인됨'과 '추정됨'을 구분한다.

| 종류 | 확인 근거 (확인됨) | 추정 근거 (추정됨) |
|---|---|---|
| 일반 DNS | UDP·TCP 53 에서 DNS 메시지를 해석함 (도메인 표시) | - |
| DoT | TCP 853 + TLS 핸드셰이크 (853 은 IANA 지정 DoT 포트), ALPN 'dot' | TCP 853 이지만 TLS 를 아직 못 봄 |
| DoQ | QUIC Initial 의 ALPN 'doq' | UDP 853 이지만 QUIC Initial 을 못 풂 |
| DoH | (패킷만으로는 확정 불가 — 내용이 일반 HTTPS 와 같다) | 알려진 DoH 서버 이름(SNI), 알려진 공용 DNS 의 IP 로 443 접속, DDR(_dns.resolver.arpa) 조회 |

443 포트라는 이유만으로 DoH 라고 하지 않는다. 암호화 DNS 는 질의 도메인을 볼 수 없으므로 도메인은 표시하지 않는다.
"""
from __future__ import annotations

import ipaddress
from collections import Counter

from netcare.encrypted import CONFIRMED, ESTIMATED

DOH_HOSTS = {
    "dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "doh.familyshield.opendns.com",
    "dns.adguard-dns.com", "dns.adguard.com", "unfiltered.adguard-dns.com", "family.adguard-dns.com", "doh.cleanbrowsing.org",
    "dns.mullvad.net", "doh.mullvad.net", "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.controld.com", "freedns.controld.com",
    "doh.xfinity.com", "public.dns.iij.jp", "dns.twnic.tw", "doh.libredns.gr", "dns.switch.ch",
}
DOH_SUFFIXES = (".dns.nextdns.io", ".nextdns.io", ".controld.com", ".cloudflare-gateway.com")
PUBLIC_RESOLVERS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google", "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "185.228.168.168": "CleanBrowsing", "76.76.2.0": "Control D",
}
KINDS = ("dns", "dot", "doq", "doh")
KIND_KO = {"dns": "일반 DNS (평문)", "dot": "DNS over TLS (DoT)", "doq": "DNS over QUIC (DoQ)", "doh": "DNS over HTTPS (DoH) 의심"}


def doh_host(name: str | None) -> bool:
    n = (name or "").lower().rstrip(".")
    return bool(n) and (n in DOH_HOSTS or n.endswith(DOH_SUFFIXES))


def resolver_of(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        return PUBLIC_RESOLVERS.get(str(ipaddress.ip_address(ip)))
    except ValueError:
        return None


class DnsClassifier:
    """흐름별 암호화 DNS 판정과 종류별 통신량 통계."""

    MAX_FLOWS = 20000

    def __init__(self):
        self.flows: dict[tuple, dict] = {}      # (client, server, port, proto) → 판정
        self.packets = Counter()
        self.bytes = Counter()
        self.ddr_clients: set = set()
        self.events: list = []

    @staticmethod
    def _key(r: dict) -> tuple | None:
        sp, dp = r.get("sport"), r.get("dport")
        if dp in (53, 853, 443) or (dp and sp and dp < sp):
            return (r.get("src"), r.get("dst"), dp, r.get("proto"))
        return (r.get("dst"), r.get("src"), sp, r.get("proto"))

    def _set(self, key, kind, status, basis, confidence=None, domain=None) -> dict:
        cur = self.flows.get(key)
        rank = {CONFIRMED: 2, ESTIMATED: 1}
        if cur and rank.get(cur["status"], 0) > rank.get(status, 0):
            return cur
        if cur is None and len(self.flows) >= self.MAX_FLOWS:
            return {"kind": kind, "status": status}
        d = {"kind": kind, "kind_label": KIND_KO[kind], "status": status, "basis": basis, "confidence": confidence,
             "client": key[0], "server": key[1], "port": key[2], "proto": key[3], "resolver": resolver_of(key[1])}
        if domain:
            d["domain"] = domain
        self.flows[key] = d
        return d

    def packet(self, r: dict, tls: dict | None = None, quic: dict | None = None) -> dict | None:
        """패킷 하나(그리고 같은 패킷에서 얻은 TLS·QUIC 결과)로 판정을 갱신하고, 이 흐름의 판정을 돌려준다."""
        proto, sp, dp = r.get("proto"), r.get("sport"), r.get("dport")
        key = self._key(r)
        if key is None:
            return None
        res = None
        if r.get("dns_id") is not None and 53 in (sp, dp):
            res = self._set(key, "dns", CONFIRMED, "UDP/TCP 53 에서 DNS 메시지를 해석함", domain=r.get("dns_qname"))
            q = (r.get("dns_qname") or "").lower()
            if q == "_dns.resolver.arpa":
                self.ddr_clients.add(r.get("src") if dp == 53 else r.get("dst"))
        elif proto == "TCP" and 853 in (sp, dp):
            if tls:
                alpn = tls.get("alpn") or []
                res = self._set(key, "dot", CONFIRMED, "TCP 853(IANA 지정 DoT 포트) 위의 TLS 핸드셰이크" + (" + ALPN 'dot'" if "dot" in alpn else ""))
            else:
                res = self.flows.get(key) or self._set(key, "dot", ESTIMATED, "TCP 853 (TLS 핸드셰이크는 아직 보지 못함)", "중간")
        elif quic and quic.get("application", "").startswith("DNS over QUIC"):
            res = self._set(key, "doq", CONFIRMED, "QUIC Initial 의 ALPN 'doq'")
        elif proto == "UDP" and 853 in (sp, dp):
            res = self.flows.get(key) or self._set(key, "doq", ESTIMATED, "UDP 853 (QUIC Initial 을 풀지 못함)", "중간")
        elif 443 in (sp, dp) and proto in ("TCP", "UDP"):
            hello = tls or (quic or {}).get("client_hello")
            name = (hello or {}).get("sni")
            ech_unconfirmed = bool(hello and hello.get("ech") and not doh_host(name))
            basis, score = [], 0
            if hello and doh_host(name):
                basis.append(f"알려진 DoH 서버 이름(SNI) {name}")
                score += 2
            if resolver_of(key[1]):
                basis.append(f"공용 DNS {resolver_of(key[1])}({key[1]})의 443 포트")
                score += 1
            if key[0] in self.ddr_clients and score:
                basis.append("이 장치가 암호화 DNS 탐색(DDR, _dns.resolver.arpa) 조회를 했음")
                score += 1
            if score:
                conf = "높음" if score >= 2 else "중간"
                res = self._set(key, "doh", ESTIMATED, " · ".join(basis), conf)
                if ech_unconfirmed:
                    res["note"] = "SNI 가 ECH 공개 이름일 수 있어 근거가 약해질 수 있어요."
            else:
                res = self.flows.get(key)
        else:
            res = self.flows.get(key)
        if res and res.get("kind") in KINDS:
            self.packets[res["kind"]] += 1
            self.bytes[res["kind"]] += r.get("length") or 0
        return res

    def snapshot(self) -> dict:
        total_b = sum(self.bytes.values())
        flows = list(self.flows.values())
        return {"packets": dict(self.packets), "bytes": dict(self.bytes),
                "encrypted_share": round((total_b - self.bytes.get("dns", 0)) / total_b, 4) if total_b else None,
                "flows": {k: sum(1 for f in flows if f["kind"] == k) for k in KINDS},
                "confirmed_flows": {k: sum(1 for f in flows if f["kind"] == k and f["status"] == CONFIRMED) for k in KINDS},
                "list": sorted((f for f in flows if f["kind"] != "dns"), key=lambda f: (f["kind"], f["server"] or ""))[:100]}
