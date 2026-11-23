"""안정성·신뢰성 개선 회귀 테스트.

1. 실측 오탐 재현: 로드밸런서 RST(정확한 SEQ, 다른 TTL), Google Cloud 연결별 TTL
2. 진짜 주입 형태는 계속 탐지: 순서 번호 밖 RST, RST 뒤 데이터, 다른 SEQ 의 RST 반복, TTL+SEQ 불일치
3. 장시간 실행 메모리: 시간 만료·상한, 상한에 닿아도 탐지가 멈추지 않음
"""
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from netcare.analysis.stats import LiveStats
from netcare.capture.parser import parse_packet
from netcare.config import DetectionConfig
from netcare.detection.detector import Detector

ME, MY_MAC, GW_MAC = "172.16.104.63", "02:00:00:00:04:63", "10:5a:95:61:a3:84"
T0 = 1_795_370_000.0


def det(**kw):
    return Detector(DetectionConfig(**kw), {ME}, {MY_MAC}, gateway_ip="172.16.104.1")


def rec(p, ts):
    q = p.__class__(bytes(p))
    q.time = ts
    return parse_packet(q, {ME}, {MY_MAC})


def down(src, ttl, l4):
    return Ether(src=GW_MAC, dst=MY_MAC) / IP(src=src, dst=ME, ttl=ttl, id=0) / l4


def up(dst, l4):
    return Ether(src=MY_MAC, dst=GW_MAC) / IP(src=ME, dst=dst, ttl=64) / l4


def types(found):
    return {a["type"] for a in found}


# ───────────── 1. 실측 오탐 재현 ─────────────
LB = "34.149.66.165"


def _lb_flow(d, port=61670, t=T0, fin=True):
    """실측 패킷 헤더 값 그대로 (2026-11-23 02:53:37, postfix-data DB): keep-alive 뒤 서버 FIN, 내 데이터+FIN, LB 의 RST 2개."""
    s, c = 17263533, 2504574746
    d.observe(rec(up(LB, TCP(sport=port, dport=443, flags="S", seq=c - 600)), t))
    d.observe(rec(down(LB, 116, TCP(sport=443, dport=port, flags="SA", seq=s - 900, ack=c - 599)), t + 0.01))
    for i in range(8):                                   # 데이터와 keep-alive (TTL 116)
        d.observe(rec(down(LB, 116, TCP(sport=443, dport=port, flags="PA", seq=s - 900 + i * 100, ack=c + 1) / Raw(b"d" * 100)), t + 0.1 + i * 0.1))
        d.observe(rec(up(LB, TCP(sport=port, dport=443, flags="A", seq=c + 1, ack=s - 800 + i * 100)), t + 0.15 + i * 0.1))
    d.observe(rec(down(LB, 116, TCP(sport=443, dport=port, flags="PA", seq=s + 100, ack=c + 1) / Raw(b"x" * 24)), t + 2))
    nx = s + 124
    if fin:
        d.observe(rec(down(LB, 116, TCP(sport=443, dport=port, flags="FA", seq=nx, ack=c + 1)), t + 2.0))
        nx += 1
    d.observe(rec(up(LB, TCP(sport=port, dport=443, flags="PA", seq=c + 1, ack=nx) / Raw(b"y" * 24)), t + 2.001))
    d.observe(rec(up(LB, TCP(sport=port, dport=443, flags="FA", seq=c + 25, ack=nx)), t + 2.001))
    return nx


def test_lb_rst_after_fin_with_different_ttl_is_not_injection():
    d = det()
    nx = _lb_flow(d)
    for k in range(2):                                   # RST 2개: TTL 108, SEQ = FIN+1 (정확), ACK 0
        d.observe(rec(down(LB, 108, TCP(sport=443, dport=61670, flags="R", seq=nx, ack=0)), T0 + 2.012 + k * 0.0001))
    assert "tcp_injection" not in types(d.evaluate(T0 + 4))


def test_lb_idle_rst_without_fin_exact_seq_is_not_injection():
    """FIN 없이 정확한 SEQ 의 RST 를 다른 TTL 로 (로드밸런서 유휴 끊기 형태). 뒤따르는 데이터가 없으면 징후 아님."""
    d = det()
    nx = _lb_flow(d, fin=False)
    d.observe(rec(down(LB, 108, TCP(sport=443, dport=61670, flags="R", seq=nx)), T0 + 3))
    d.observe(rec(down(LB, 108, TCP(sport=443, dport=61670, flags="R", seq=nx)), T0 + 3.0001))   # 같은 SEQ 중복
    assert "tcp_injection" not in types(d.evaluate(T0 + 6))


GCP = "34.104.35.123"


def test_gcp_per_connection_ttl_is_not_spoofing():
    """실측: 같은 Google Cloud 주소가 연결마다 TTL 117 또는 54 (연결 안에서는 일정)."""
    d = det()
    ttls = [117, 117, 117, 117, 54, 54, 54, 117, 54, 117]
    for c, ttl in enumerate(ttls):
        t, sp = T0 + c * 42, 53000 + c
        d.observe(rec(up(GCP, TCP(sport=sp, dport=443, flags="S", seq=1000)), t))
        d.observe(rec(down(GCP, ttl, TCP(sport=443, dport=sp, flags="SA", seq=5000, ack=1001)), t + 0.02))
        for i in range(12):
            d.observe(rec(down(GCP, ttl, TCP(sport=443, dport=sp, flags="PA", seq=5001 + i * 200, ack=1001) / Raw(b"g" * 200)), t + 0.05 + i * 0.01))
        found = d.evaluate(t + 1)
        assert "ip_spoof_suspect" not in types(found), c
    assert not any(e[0].startswith("ttl") for b in d.adv.secs.values() for e in b.spoof)


def test_ttl_alone_inside_connection_is_only_auxiliary():
    """연결 안에서 TTL 만 바뀌고 SEQ·ACK 는 정상 → 약한 징후로 기록하되 알림은 만들지 않음."""
    d = det()
    sp = 52000
    d.observe(rec(up(GCP, TCP(sport=sp, dport=443, flags="S", seq=1000)), T0))
    d.observe(rec(down(GCP, 117, TCP(sport=443, dport=sp, flags="SA", seq=5000, ack=1001)), T0 + 0.02))
    for i in range(30):
        ttl = 117 if i < 5 else 60
        d.observe(rec(down(GCP, ttl, TCP(sport=443, dport=sp, flags="PA", seq=5001 + i * 100, ack=1001) / Raw(b"g" * 100)), T0 + 0.1 + i * 0.05))
    assert "ip_spoof_suspect" not in types(d.evaluate(T0 + 3))
    kinds = [e[0] for b in d.adv.secs.values() for e in b.spoof]
    assert kinds and set(kinds) == {"ttl"}


# ───────────── 2. 진짜 주입 형태는 계속 탐지 ─────────────
def test_onpath_rst_injection_followed_by_server_data_is_flagged():
    """경로 위 장비가 정확한 SEQ 의 RST 를 다른 TTL 로 끼워 넣고, 진짜 서버는 데이터를 계속 보냄."""
    d = det()
    nx = _lb_flow(d, fin=False)
    d.observe(rec(down(LB, 40, TCP(sport=443, dport=61670, flags="R", seq=nx)), T0 + 3))
    d.observe(rec(down(LB, 116, TCP(sport=443, dport=61670, flags="PA", seq=nx, ack=2504574771) / Raw(b"z" * 300)), T0 + 3.05))
    hit = [a for a in d.evaluate(T0 + 5) if a["type"] == "tcp_injection"]
    assert hit and set(hit[0]["evidence"]["indicators"]) >= {"rst_ttl", "data_after_rst"}


def test_rst_burst_with_different_seqs_is_flagged():
    d = det()
    nx = _lb_flow(d, fin=False)
    d.observe(rec(down(LB, 40, TCP(sport=443, dport=61670, flags="R", seq=nx)), T0 + 3))
    d.observe(rec(down(LB, 40, TCP(sport=443, dport=61670, flags="R", seq=nx + 1)), T0 + 3.001))
    hit = [a for a in d.evaluate(T0 + 5) if a["type"] == "tcp_injection"]
    assert hit and hit[0]["evidence"]["indicators"].get("rst_ttl") == 2


def test_rst_acking_unsent_data_is_flagged():
    d = det()
    nx = _lb_flow(d, fin=False)
    for k in range(2):
        d.observe(rec(down(LB, 116, TCP(sport=443, dport=61670 , flags="RA", seq=nx, ack=(2504574771 + 5_000_000 + k) % (1 << 32))), T0 + 3 + k * 0.01))
    hit = [a for a in d.evaluate(T0 + 5) if a["type"] == "tcp_injection"]
    assert hit and hit[0]["evidence"]["indicators"].get("rst_ack") == 2


def test_ttl_plus_bad_seq_counts_as_strong_spoof_indicator():
    d = det(spoof_min_indicators=5)
    sp = 52001
    d.observe(rec(up(GCP, TCP(sport=sp, dport=443, flags="S", seq=1000)), T0))
    d.observe(rec(down(GCP, 117, TCP(sport=443, dport=sp, flags="SA", seq=5000, ack=1001)), T0 + 0.02))
    for i in range(5):
        d.observe(rec(down(GCP, 117, TCP(sport=443, dport=sp, flags="PA", seq=5001 + i * 100, ack=1001) / Raw(b"g" * 100)), T0 + 0.1 + i * 0.05))
    for i in range(6):                                   # TTL 도 다르고 SEQ 가 연결 상태와 전혀 맞지 않음
        d.observe(rec(down(GCP, 60, TCP(sport=443, dport=sp, flags="PA", seq=(5001 + 900_000_000 + i * 100) % (1 << 32), ack=1001) / Raw(b"e" * 100)),
                      T0 + 1 + i * 0.05))
    hit = [a for a in d.evaluate(T0 + 3) if a["type"] == "ip_spoof_suspect"]
    assert hit and hit[0]["evidence"]["indicators"].get("ttl_seq") == 6


# ───────────── 3. 장시간 실행 메모리 ─────────────
def test_housekeeping_expires_stale_state():
    d = det()
    a = d.adv
    for i in range(500):
        a.target_ok[(f"198.51.{i // 250}.{i % 250}", 443)] = T0
        a.in_synack_for_server[(f"203.0.{i // 250}.{i % 250}", 1, ME, 8080)] = T0
        a.dns_q[(i, ME)] = ("8.8.8.8", f"n{i}.example", T0)
    a.housekeep(T0 + 400)
    assert not a.target_ok and not a.in_synack_for_server and not a.dns_q


def test_dns_tracking_keeps_working_after_many_queries():
    """예전: DNS 질의 기록이 20000개에 닿으면 새 질의를 기록하지 않아 DNS 위조 탐지·RTT 측정이 조용히 멈췄다."""
    d = det()
    t = T0
    for i in range(25000):
        d.observe(rec(up("8.8.8.8", UDP(sport=40000 + i % 20000, dport=53) / Raw(b"\x00" * 12)), t))   # DNS 파싱 없이 시간만 흐르게
        if i % 100 == 0:
            t += 5
            d.evaluate(t)
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    q = up("8.8.8.8", UDP(sport=55555, dport=53) / DNS(id=4242, rd=1, qd=DNSQR(qname="late.example")))
    for i in range(25000):
        d.adv.dns_q[(i, "10.9.9.9")] = ("8.8.8.8", "x", t)       # 오래된(만료 대상) 질의로 가득 채움
    d.evaluate(t + 60)                                           # 정리
    d.observe(rec(q, t + 60))
    assert (4242, ME) in d.adv.dns_q
    r = Ether(src=GW_MAC, dst=MY_MAC) / IP(src="9.9.9.9", dst=ME) / UDP(sport=53, dport=55555) / DNS(id=4242, qr=1, qd=DNSQR(qname="late.example"),
                                                                                                    an=DNSRR(rrname="late.example", rdata="1.2.3.4"))
    d.observe(rec(r, t + 60.01))
    assert any(e[0] == "wrong_server" for b in d.adv.secs.values() for e in b.dns_events)


def test_ttl_history_keeps_learning_new_sources_after_cap():
    d = det()
    a = d.adv
    a.TTL_HIST_MAX = 100
    for i in range(300):
        d.observe(rec(down(f"45.{i // 250}.{i % 250}.7", 50, UDP(sport=443, dport=50000) / Raw(b"q")), T0 + i * 0.001))
    assert len(a.ttl_hist) <= 101 and ("45.1.49.7", "UDP") in a.ttl_hist


def test_live_stats_keys_are_capped_and_top_talkers_kept():
    s = LiveStats()
    s.MAX_KEYS = 1000
    base = {"length": 100, "proto": "TCP", "direction": "down", "dst": ME, "service_port": 443, "ip_version": 4}
    for i in range(3000):
        s.add({**base, "ts": T0 + i * 0.001, "src": f"100.64.{i // 250}.{i % 250}"})
    for i in range(500):
        s.add({**base, "ts": T0 + 3 + i * 0.001, "src": "8.8.4.4"})
    snap = s.snapshot(T0 + 4)
    assert len(s.src_packets) <= 1000
    assert snap["unique_approx"] is True and snap["unique_src"] >= 3000
    assert snap["top_src"][0]["ip"] == "8.8.4.4" and snap["top_src"][0]["packets"] == 500


def test_housekeeping_runs_even_when_traffic_stops():
    """예전: 평가 창이 비면(트래픽 정지) Detector.evaluate 가 하위 탐지기 정리 전에 끝나 상태가 그대로 남았다."""
    d = det()
    for i in range(200):
        sp = 40000 + i
        d.observe(rec(up(GCP, TCP(sport=sp, dport=443, flags="S", seq=1)), T0 + i * 0.01))
        d.observe(rec(down(GCP, 117, TCP(sport=443, dport=sp, flags="SA", seq=9, ack=2)), T0 + i * 0.01 + 0.005))
        d.observe(rec(down(GCP, 117, TCP(sport=443, dport=sp, flags="PA", seq=10, ack=2) / Raw(b"x" * 50)), T0 + i * 0.01 + 0.006))
    d.evaluate(T0 + 3)
    assert d.adv.target_ok and d.integ.flows and d.adv.conn_ttl
    for k in range(40):                          # 패킷 없이 20분 동안 평가만
        d.evaluate(T0 + 3 + (k + 1) * 30)
    assert not d.adv.target_ok and not d.integ.flows and not d.adv.conn_ttl and not d.adv.seqs and not d.compat.open_ports


def test_ipv6_unspecified_source_for_dad_and_mld_is_not_spoofing():
    """실측 (6시간 실측 2026-11-23 23:52·00:21): LAN 장치가 주소 중복 확인(DAD)·MLD 보고를 '::' 에서 ff02:: 로 보냄 → 정상."""
    from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6MLReport2, IPv6, IPv6ExtHdrHopByHop, RouterAlert
    d = det()
    other = "00:19:66:cb:8b:08"
    for i in range(10):
        d.observe(rec(Ether(src=other, dst="33:33:ff:12:34:56") / IPv6(src="::", dst="ff02::1:ff12:3456", hlim=255)
                      / ICMPv6ND_NS(tgt="fe80::1234:5678:9abc:def0"), T0 + i * 0.5))
        d.observe(rec(Ether(src=other, dst="33:33:00:00:00:16") / IPv6(src="::", dst="ff02::16", hlim=1)
                      / IPv6ExtHdrHopByHop(options=[RouterAlert()]) / ICMPv6MLReport2(), T0 + i * 0.5 + 0.1))
    assert "ip_spoof_suspect" not in types(d.evaluate(T0 + 6))


def test_ipv6_unspecified_source_to_unicast_is_still_flagged():
    """'::' 에서 유니캐스트로 가는 패킷은 표준에 없음 → 계속 특수 주소 징후."""
    from scapy.layers.inet6 import IPv6
    d = det()
    for i in range(10):
        d.observe(rec(Ether(src=GW_MAC, dst=MY_MAC) / IPv6(src="::", dst="2001:db8::63", hlim=64) / TCP(sport=4000 + i, dport=80, flags="S"), T0 + i * 0.3))
    assert any(e[0] == "bogon" for b in d.adv.secs.values() for e in b.spoof)


def test_dad_plus_weak_ttl_in_same_window_is_not_spoofing():
    """실측 (6시간 실측 2026-11-24 04:08): 같은 10초 안에 '::' DAD 3개 + 로드밸런서 TTL 약한 징후 2개 (시험은 DAD 4개로 임계 5를 넘김) → 둘 다 정상이므로 알림 없음."""
    from scapy.layers.inet6 import ICMPv6ND_NS, IPv6
    d = det()
    sp = 52100
    d.observe(rec(up(GCP, TCP(sport=sp, dport=443, flags="S", seq=1000)), T0))
    d.observe(rec(down(GCP, 117, TCP(sport=443, dport=sp, flags="SA", seq=5000, ack=1001)), T0 + 0.02))
    for i in range(30):
        ttl = 117 if i < 5 else 60
        d.observe(rec(down(GCP, ttl, TCP(sport=443, dport=sp, flags="PA", seq=5001 + i * 100, ack=1001) / Raw(b"g" * 100)), T0 + 0.1 + i * 0.05))
    for i in range(4):
        d.observe(rec(Ether(src="00:19:66:cb:8b:08", dst="33:33:ff:12:34:56") / IPv6(src="::", dst="ff02::1:ff12:3456", hlim=255)
                      / ICMPv6ND_NS(tgt="fe80::1234:5678:9abc:def0"), T0 + 1 + i * 0.5))
    assert any(e[0] == "ttl" for b in d.adv.secs.values() for e in b.spoof)   # 약한 징후는 기록됨
    assert "ip_spoof_suspect" not in types(d.evaluate(T0 + 4))
