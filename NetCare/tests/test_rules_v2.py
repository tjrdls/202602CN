"""4단계 확장 규칙(비정상 패킷 크기·프로토콜 비율 이상·NXDOMAIN 급증)과 규칙 카탈로그, 종료 정리 테스트."""
import threading
import time

from netcare.config import DetectionConfig
from netcare.detection.detector import Detector
from netcare.detection.rules import RULES, rule_catalog
from netcare.diagnosis.explainer import TYPE_LABELS, _EXPLAINERS, explain
from netcare.testdata import synthetic
from tests.test_detection import replay, types

T0 = 1_700_000_000
ME, PEER, DNS = "192.168.77.10", "198.51.100.7", "192.168.77.1"


def base_rec(ts, **kw):
    r = {"ts": ts, "src": PEER, "dst": ME, "length": 98, "proto": "UDP", "sport": 40000, "dport": 40001, "flags": None, "ttl": 60,
         "service_port": None, "src_mac": "02:00:00:00:00:02", "dst_mac": "02:00:00:00:77:10", "ip_version": 4, "payload_len": 56,
         "dns_id": None, "dns_qr": None, "dns_rcode": None, "dns_qname": None, "dns_qtype": None, "dns_answers": None,
         "icmp_type": None, "seq": None, "direction": "down", "service": ""}
    r.update(kw)
    return r


def new_det():
    return Detector(DetectionConfig(), {ME}, {"02:00:00:00:77:10"}, gateway_ip=DNS)


def test_large_icmp_packets_flagged_as_info_suspect():
    det = new_det()
    for i in range(12):
        det.observe(base_rec(T0 + i * 0.5, proto="ICMP", icmp_type=8, length=1400, payload_len=1372, sport=None, dport=None))
    found = det.evaluate(T0 + 8)
    hit = [a for a in found if a["type"] == "packet_size_anomaly"]
    assert hit and hit[0]["severity"] == "info" and hit[0]["evidence"]["certainty"] == "suspected" and hit[0]["evidence"]["kind"] == "ICMP"
    ex = explain(hit[0], {"local_ips": {ME}})
    assert "의심" in ex["title"] and ex["false_positive"]


def test_small_icmp_not_flagged():
    det = new_det()
    for i in range(30):
        det.observe(base_rec(T0 + i * 0.2, proto="ICMP", icmp_type=8, length=98, payload_len=56, sport=None, dport=None))
    assert "packet_size_anomaly" not in types(det.evaluate(T0 + 8))


def test_nxdomain_surge_needs_many_distinct_names():
    det = new_det()
    # 같은 도메인만 30번 NXDOMAIN → 도메인 수 부족으로 미탐 (오타 반복은 급증이 아님)
    for i in range(30):
        det.observe(base_rec(T0 + i * 0.2, src=DNS, dst=ME, sport=53, dport=5000 + i, dns_id=i, dns_qr=1, dns_rcode=3, dns_qname="typo.example"))
    assert "dns_nxdomain_surge" not in types(det.evaluate(T0 + 8))
    det = new_det()
    for i in range(25):
        det.observe(base_rec(T0 + i * 0.2, src=DNS, dst=ME, sport=53, dport=5000 + i, dns_id=i, dns_qr=1, dns_rcode=3, dns_qname=f"x{i}.example"))
    hit = [a for a in det.evaluate(T0 + 8) if a["type"] == "dns_nxdomain_surge"]
    assert hit and hit[0]["severity"] == "info" and hit[0]["evidence"]["distinct_names"] == 25


def test_proto_ratio_shift_after_learning():
    det = new_det()
    # 70초 동안 TCP 위주(초당 20개)로 기준선 학습
    for s in range(70):
        for i in range(20):
            det.observe(base_rec(T0 + s + i / 25, proto="TCP", flags="A", sport=443, dport=50000 + i, length=120, payload_len=60))
        det.evaluate(T0 + s + 1)
    assert det.adv.proto_learned >= 60 and det.adv.proto_base["TCP"] > 0.9
    # 이후 10초 동안 UDP 가 초당 200개 → 비율 급변
    t1 = T0 + 70
    for s in range(10):
        for i in range(200):
            det.observe(base_rec(t1 + s + i / 250, proto="UDP", sport=3478, dport=50000 + i, length=200, payload_len=150))
        found = det.evaluate(t1 + s + 1)
    hit = [a for a in found if a["type"] == "proto_ratio_shift"]
    assert hit and hit[0]["severity"] == "info" and hit[0]["evidence"]["proto"] == "UDP"


def test_proto_ratio_shift_silent_on_quiet_network():
    det = new_det()
    for s in range(70):
        for i in range(20):
            det.observe(base_rec(T0 + s + i / 25, proto="TCP", flags="A", sport=443, dport=50000 + i))
        det.evaluate(T0 + s + 1)
    t1 = T0 + 70
    for s in range(10):   # UDP 100% 지만 초당 5개 → PPS 기준 미달이라 조용
        for i in range(5):
            det.observe(base_rec(t1 + s + i / 10, proto="UDP", sport=3478, dport=50000 + i))
        found = det.evaluate(t1 + s + 1)
    assert "proto_ratio_shift" not in types(found)


def test_new_rules_do_not_fire_on_existing_test_scenarios():
    """기존 테스트 데이터 5종에서 새 규칙 3종이 오탐을 내지 않아야 한다 (반복 방지)."""
    new = {"packet_size_anomaly", "proto_ratio_shift", "dns_nxdomain_surge", "checksum_error", "tcp_injection", "udp_replay"}
    for name in synthetic.SCENARIOS:
        assert not (types(replay(name)) & new), name


def test_rule_catalog_covers_every_type_and_fills_thresholds():
    cfg = DetectionConfig(syn_threshold=77)
    rs = rule_catalog(cfg)
    assert len(rs) == len(RULES) == 25
    assert {r["type"] for r in rs} == set(TYPE_LABELS) == set(_EXPLAINERS)
    syn = next(r for r in rs if r["type"] == "syn_surge")
    assert "77" in syn["condition"] and {"key": "syn_threshold", "value": 77} in syn["thresholds"]
    for r in rs:
        assert r["false_positives"] and r["limits"] and r["environments"] and r["severity"] and r["certainty_label"]


def test_engine_shutdown_stops_threads(tmp_path):
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    from netcare.capture.engine import Engine
    cfg = ConfigStore(tmp_path / "config.json")
    db = Database(tmp_path / "t.db")
    eng = Engine(cfg, db, run_probe=False)
    eng.run_test("normal")
    time.sleep(1.0)
    before = {t.name for t in threading.enumerate()}
    assert any(n.startswith("netcare-") for n in before)
    eng.shutdown()
    deadline = time.time() + 5
    while time.time() < deadline and any(t.name.startswith("netcare-") and t.is_alive() for t in threading.enumerate()):
        time.sleep(0.1)
    alive = [t.name for t in threading.enumerate() if t.name.startswith("netcare-") and t.is_alive()]
    assert not alive, alive


def test_dns_sd_and_reverse_lookup_nxdomain_is_not_dns_failure():
    """실측 오탐 회귀: macOS 의 DNS-SD 탐색(…_dns-sd._udp.x.in-addr.arpa)은 항상 NXDOMAIN 이라 DNS 장애가 아니다."""
    det = new_det()
    for i in range(20):
        q = f"lb._dns-sd._udp.{i}.64.168.192.in-addr.arpa"
        det.observe(base_rec(T0 + i * 0.3, src=ME, dst=DNS, sport=5000 + i, dport=53, dns_id=i, dns_qr=0, dns_qname=q))
        det.observe(base_rec(T0 + i * 0.3 + 0.01, src=DNS, dst=ME, sport=53, dport=5000 + i, dns_id=i, dns_qr=1, dns_rcode=3, dns_qname=q))
    assert "dns_failure" not in types(det.evaluate(T0 + 8))
    det = new_det()   # 일반 도메인의 SERVFAIL 은 여전히 실패로 센다
    for i in range(20):
        q = f"site{i}.example.com"
        det.observe(base_rec(T0 + i * 0.3, src=ME, dst=DNS, sport=5000 + i, dport=53, dns_id=i, dns_qr=0, dns_qname=q))
        det.observe(base_rec(T0 + i * 0.3 + 0.01, src=DNS, dst=ME, sport=53, dport=5000 + i, dns_id=i, dns_qr=1, dns_rcode=2, dns_qname=q))
    assert "dns_failure" in types(det.evaluate(T0 + 8))
