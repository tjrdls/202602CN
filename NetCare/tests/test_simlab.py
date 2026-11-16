"""Simulation Lab 테스트: 재현성, 데이터 분리, 실제 시스템 명령 미실행, 12종 탐지, 평가 지표."""
import re
import tempfile
from collections import defaultdict
from pathlib import Path

import pytest

from netcare.capture.parser import parse_packet
from netcare.config import ConfigStore, DetectionConfig
from netcare.detection.detector import Detector
from netcare.simlab import evaluate
from netcare.simlab import network as N
from netcare.simlab.scenarios import SCENARIOS, LabGenerator

T0 = 1_800_000_000


def offline(sid, **params):
    """생성기 → 탐지기 직접 연결 (빠른 검증용). 탐지 유형별 처음 탐지된 초를 돌려준다."""
    g = LabGenerator(sid, params)
    det = Detector(DetectionConfig(), {N.CLIENT_IP}, {N.CLIENT_MAC}, N.GW_IP)
    eff = N.Effects()
    first = {}
    for s in range(g.p["duration"]):
        for t, p, _ in g.step(s, eff):
            p.time = T0 + t
            det.observe(parse_packet(p, {N.CLIENT_IP}, {N.CLIENT_MAC}, source="sim", store_raw=False))
        for a in det.evaluate(T0 + s + 1):
            first.setdefault(a["type"], s + 1)
    return g, first


@pytest.mark.parametrize("sid", [s for s in SCENARIOS if s != "normal"])
def test_each_scenario_detected_with_expected_type(sid):
    g, first = offline(sid)
    spec = SCENARIOS[sid]
    hit = [t for t in spec.expected if t in first]
    assert hit, f"{sid}: 기대 유형 {spec.expected} 미탐지, 실제 {first}"
    assert first[hit[0]] > g.p["attack_start"]                     # 공격 시작 전에는 탐지되지 않음
    unrelated = set(first) - spec.expected - spec.acceptable
    assert not unrelated, f"{sid}: 관련 없는 탐지 {unrelated}"


def test_normal_background_has_zero_alerts():
    for seed in (1, 2, 3):
        _, first = offline("normal", seed=seed)
        assert first == {}, first


def test_low_intensity_is_missed():
    """기준 아래 강도는 탐지되지 않는 것이 정상 (과대 탐지 방지 확인)."""
    _, first = offline("repeated", intensity=0.2)     # 초당 2회 → 10초 20회 < 기준 30회
    assert "repeated_connection" not in first


def test_generator_reproducible():
    def digest(seed):
        g = LabGenerator("dns_spoof", {"seed": seed})
        eff = N.Effects()
        return [(round(t, 6), bytes(p)) for s in range(g.p["duration"]) for t, p, _ in g.step(s, eff)]
    assert digest(5) == digest(5)
    assert digest(5) != digest(6)


def test_simlab_never_sends_packets_static():
    """실험실 코드에는 패킷 전송 함수가 없어야 한다."""
    root = Path(__file__).resolve().parent.parent / "netcare" / "simlab"
    for f in root.glob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert not re.search(r"\b(sendp?|srp?1?|sendpfast|srloop)\s*\(", src), f
        assert not re.search(r"^\s*(from|import)\s+netcare\.remediation", src, re.M), f   # 실제 조치 모듈 import 금지


def test_score_hand_computed():
    spec = SCENARIOS["repeated"]
    params = {"duration": 10, "attack_start": 3, "attack_end": 6}
    base = 1000.0
    # 공격 구간 (3,6] = 4,5,6 / 유예 (6,16] / 탐지 5~7초
    an = [{"type": "repeated_connection", "severity": "warning", "detected_at": base + 5, "last_seen": base + 7},
          {"type": "port_scan", "severity": "warning", "detected_at": base + 9, "last_seen": base + 9}]
    sc = evaluate.score(spec, params, an, base, window_sec=10)
    assert (sc["tp"], sc["fn"]) == (2, 1)           # 5,6 TP / 4 FN
    assert sc["fp"] == 1                             # 9초의 무관한 포트 스캔 (유예 구간이지만 무관 유형)
    assert sc["tn"] == 3                             # 1,2,3
    assert sc["latency_sec"] == 2.0
    assert sc["precision"] == round(2 / 3, 4) and sc["recall"] == round(2 / 3, 4)
    assert sc["fpr"] == 0.25


@pytest.fixture(scope="module")
def lab_env():
    from netcare.simlab.lab import SimLab
    from netcare.storage.db import Database
    d = Path(tempfile.mkdtemp(prefix="netcare-lab-"))
    main_db = Database(d / "netcare.db")             # 실제 데이터 DB (비어 있어야 함)
    lab = SimLab(ConfigStore(d / "config.json"), d)
    yield lab, main_db, d
    lab.shutdown()


def test_lab_end_to_end_separation_and_no_system_calls(lab_env, monkeypatch):
    lab, main_db, d = lab_env
    from netcare.remediation import system

    def boom(*a, **k):
        raise AssertionError("실험실에서 실제 시스템 명령이 실행됨")
    monkeypatch.setattr(system, "run", boom)
    monkeypatch.setattr(system, "run_script", boom)
    eid = lab.start("syn_flood", {"seed": 3}, "auto", wait=True)
    e = lab.experiment(eid)
    assert e["status"] == "completed" and e["detected"] == 1
    assert e["response"]["first_action"] == "host_block" and e["response"]["success"] is True
    assert e["response"]["comparison"]["after"] == 0           # 가상 방화벽 이후 공격자에게 응답하지 않음
    assert Path(e["pcap_path"]).exists()
    # 실제 데이터 DB 에는 아무것도 기록되지 않음
    for t in ("sessions", "packets", "anomalies", "actions"):
        assert main_db.query_one(f"SELECT COUNT(*) AS n FROM {t}")["n"] == 0
    # 실험실 DB 의 모든 기록은 sim 출처
    assert {r["source"] for r in lab.db.query("SELECT DISTINCT source FROM sessions")} == {"sim"}
    assert {r["source"] for r in lab.db.query("SELECT DISTINCT source FROM anomalies")} <= {"sim"}
    assert all(r["simulated"] == 1 for r in lab.db.query("SELECT simulated FROM actions"))


def test_lab_experiment_reproducible(lab_env):
    lab, _, _ = lab_env
    a = lab.experiment(lab.start("port_scan", {"seed": 11}, "none", wait=True))
    b = lab.experiment(lab.start("port_scan", {"seed": 11}, "none", wait=True))
    assert a["digest"] == b["digest"]
    for k in ("packets", "detected", "latency_sec", "tp", "fp", "fn", "tn"):
        assert a[k] == b[k], k


def test_lab_normal_measures_false_positives(lab_env):
    lab, _, _ = lab_env
    e = lab.experiment(lab.start("normal", {"seed": 2}, "none", wait=True))
    assert e["fp"] == 0 and e["tn"] > 0 and e["fpr"] == 0.0


def test_real_network_false_positive_regressions():
    """실제 네트워크 재검증에서 발견한 오탐 3건이 다시 생기지 않는지 확인."""
    import ipaddress
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import ARP, Ether
    me, mymac = "172.16.104.99", "00:e0:4c:30:36:50"
    det = Detector(DetectionConfig(), {me}, {mymac}, "172.16.104.1")
    det.local_nets = [ipaddress.ip_network("172.16.104.0/22")]
    pkts = []
    for i in range(6):   # 서브넷 밖 192.168.1.1 을 여러 장비가 각자 주장 (기본 IP 장비들)
        mac = f"08:8a:f1:00:00:{i:02x}"
        pkts.append(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.1", hwsrc=mac, pdst="192.168.1.255"))
        pkts.append(Ether(src=mac, dst=mymac) / IP(src="192.168.1.1", dst=me) / UDP(sport=1900, dport=40000) / b"x")
    for i in range(12):  # mDNS 질의 (멀티캐스트라 1:1 응답 없음)
        pkts.append(Ether(src=mymac, dst="01:00:5e:00:00:fb") / IP(src=me, dst="224.0.0.251") / UDP(sport=5353, dport=5353) /
                    DNS(id=0, qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR")))
    for k, p in enumerate(pkts):
        p.time = T0 + k * 0.3
        det.observe(parse_packet(p, {me}, {mymac}, store_raw=False))
    found = []
    for s in range(1, 15):
        found += det.evaluate(T0 + s)
    assert not {a["type"] for a in found} & {"arp_spoof", "ip_spoof_suspect", "dns_failure"}, found
