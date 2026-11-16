"""이상 탐지 규칙 테스트: [테스트 데이터] 시나리오를 오프라인으로 재생해 탐지 결과를 확인한다."""
import pytest

from netcare.capture.parser import parse_packet
from netcare.config import DetectionConfig
from netcare.detection.detector import Detector, Ewma
from netcare.testdata import synthetic

T0 = 1_700_000_000


def replay(name: str, cfg: DetectionConfig | None = None):
    det = Detector(cfg or DetectionConfig(), {synthetic.LOCAL_IP})
    found = []
    for sec, pkts in synthetic.generate(name):
        for i, p in enumerate(pkts):
            p.time = T0 + sec + i / (len(pkts) + 1)
            det.observe(parse_packet(p, {synthetic.LOCAL_IP}, {synthetic.LOCAL_MAC}, source="test", store_raw=False))
        found += det.evaluate(T0 + sec + 1)
    for extra in range(1, 6):  # 무응답 DNS 판정 등을 위해 몇 초 더 평가
        found += det.evaluate(T0 + synthetic.SCENARIOS[name]["duration"] + extra)
    return found


def types(found, sev=None):
    return {a["type"] for a in found if sev is None or a["severity"] == sev}


def test_normal_has_no_warnings():
    found = replay("normal")
    assert not [a for a in found if a["severity"] in ("warning", "danger")], found


def test_syn_flood_detected_as_danger():
    found = replay("syn_flood")
    syn = [a for a in found if a["type"] == "syn_surge"]
    assert syn and syn[0]["src"] == "203.0.113.50"
    assert max(a["severity"] for a in syn) == "danger"
    ev = syn[-1]["evidence"]
    assert ev["completed"] == 0 and ev["syn_ack"] > 0  # 응답은 했지만 핸드셰이크 미완료
    assert "repeated_connection" in types(found)


def test_port_scan_detected():
    found = replay("port_scan")
    scan = [a for a in found if a["type"] == "port_scan"]
    assert scan and scan[0]["src"] == "198.51.100.23"
    assert scan[-1]["evidence"]["distinct_ports"] >= 40


def test_dns_failure_detected():
    found = replay("dns_failure")
    dns = [a for a in found if a["type"] == "dns_failure"]
    assert dns
    ev = dns[-1]["evidence"]
    assert ev["error_responses"] > 0 and ev["unanswered"] > 0


def test_traffic_surge_false_positive_mitigation():
    found = replay("traffic_surge")
    assert "traffic_surge" in types(found)
    flood = [a for a in found if a["type"] == "ip_packet_flood"]
    assert flood, "과다 패킷 후보는 나와야 함"
    # 상대가 ACK 로 응답하는 양방향 다운로드 → 한 단계 낮춘 등급, 위험(danger) 아님
    assert all(a["evidence"]["bidirectional"] for a in flood)
    assert all(a["severity"] != "danger" for a in flood)
    # 443 집중은 흔한 서비스 → 정보 등급
    assert all(a["severity"] == "info" for a in found if a["type"] == "port_concentration")


def test_whitelist_suppresses():
    cfg = DetectionConfig(whitelist=["203.0.113.0/24"])
    assert not [a for a in replay("syn_flood", cfg) if a.get("src") == "203.0.113.50"]


def test_thresholds_are_configurable():
    cfg = DetectionConfig(syn_threshold=100000, repeat_conn_threshold=100000)
    assert "syn_surge" not in types(replay("syn_flood", cfg))


def test_ewma_zscore_baseline():
    e = Ewma(alpha=0.1)
    for x in [100, 110, 90, 105, 95] * 20:
        e.update(x)
    assert 95 < e.mean < 105 and e.std > 0
    assert (1000 - e.mean) / e.std > 4  # 급증은 z-score 로 구분됨


def test_dns_partial_answer_is_not_failure():
    """A 질의는 성공하고 AAAA 질의만 무응답인 실제 네트워크 사례 → 실패로 판정하지 않음 (오탐 방지)."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    det = Detector(DetectionConfig(), {"10.0.0.5"})
    t = T0
    for i in range(10):
        name = f"site{i}.example"
        qa = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=1000 + i, dport=53) / DNS(id=100 + i, qd=DNSQR(qname=name, qtype="A"))
        q6 = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=2000 + i, dport=53) / DNS(id=200 + i, qd=DNSQR(qname=name, qtype="AAAA"))
        ra = Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=1000 + i) / \
            DNS(id=100 + i, qr=1, qd=DNSQR(qname=name, qtype="A"), an=DNSRR(rrname=name, rdata="192.0.2.1"))
        for p in (qa, q6, ra):
            p.time = t + i * 0.1
            det.observe(parse_packet(p, {"10.0.0.5"}, set(), store_raw=False))
    found = []
    for s in range(1, 12):
        found += det.evaluate(t + s)
    assert not [a for a in found if a["type"] == "dns_failure"], found


def test_successful_repeated_connections_not_flagged():
    """정상적으로 완료되는 반복 연결(폴링 등)은 '반복 연결 시도'로 경고하지 않는다 (실제 루프백 실험에서 발견한 오탐)."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    det = Detector(DetectionConfig(), {"10.0.0.5"})
    for i in range(40):
        sp = 40000 + i
        for j, (src, dst, s, d, fl) in enumerate([("10.0.0.5", "10.0.0.9", sp, 8080, "S"), ("10.0.0.9", "10.0.0.5", 8080, sp, "SA"),
                                                  ("10.0.0.5", "10.0.0.9", sp, 8080, "A")]):
            p = Ether() / IP(src=src, dst=dst) / TCP(sport=s, dport=d, flags=fl)
            p.time = T0 + i * 0.05 + j * 0.001
            det.observe(parse_packet(p, {"10.0.0.5"}, set(), store_raw=False))
    found = det.evaluate(T0 + 3)
    assert not [a for a in found if a["type"] in ("repeated_connection", "syn_surge")], found
