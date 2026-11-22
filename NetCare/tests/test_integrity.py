"""패킷 무결성 탐지 테스트: 체크섬 오류, TCP 주입, UDP 재전송(리플레이)."""
import struct

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from netcare.capture.parser import checksum_status, parse_packet
from netcare.config import DetectionConfig
from netcare.detection.detector import Detector
from netcare.detection.integrity import parse_seq_ports
from netcare.detection.rules import rule_catalog
from netcare.diagnosis.explainer import explain

ME, MY_MAC = "192.168.77.10", "02:00:00:00:77:10"
PEER = "203.0.113.9"
T0 = 1_700_000_000


def det(**kw):
    return Detector(DetectionConfig(**kw), {ME}, {MY_MAC}, gateway_ip="192.168.77.1")


def built(p, ts):
    q = p.__class__(bytes(p))
    q.time = ts
    return q


def rec_of(p, ts):
    return parse_packet(built(p, ts), {ME}, {MY_MAC})


def eth_in():
    return Ether(src="02:00:00:00:00:01", dst=MY_MAC)


def types(found):
    return {a["type"] for a in found}


# ─────────────── 체크섬 ───────────────
def test_checksum_status_detects_bit_flip():
    good = built(eth_in() / IP(src=PEER, dst=ME) / UDP(sport=5000, dport=6000) / Raw(b"hello world!"), T0)
    st = checksum_status(good)
    assert st == {"ip": True, "l4": True, "l4_proto": "UDP"}
    raw = bytearray(bytes(good))
    raw[-1] ^= 0x01                       # 페이로드 1비트 변조 (체크섬은 그대로)
    flipped = Ether(bytes(raw))
    assert checksum_status(flipped)["l4"] is False
    tcp = built(eth_in() / IP(src=PEER, dst=ME) / TCP(sport=443, dport=50000, flags="PA") / Raw(b"x" * 40), T0)
    assert checksum_status(tcp)["l4"] is True


def test_checksum_error_rule_fires_only_for_incoming_bad_packets():
    d = det()
    for i in range(12):
        p = eth_in() / IP(src=PEER, dst=ME) / UDP(sport=5000, dport=6000, chksum=0x1234) / Raw(b"data%02d" % i)
        d.observe(rec_of(p, T0 + i * 0.3))
    hit = [a for a in d.evaluate(T0 + 6) if a["type"] == "checksum_error"]
    assert hit and hit[0]["src"] == PEER and hit[0]["evidence"]["certainty"] == "suspected" and hit[0]["evidence"]["layers"].get("UDP") == 12
    assert "체크섬" in explain(hit[0], {"local_ips": {ME}})["title"]
    # 내가 보낸 패킷의 틀린 체크섬(NIC 오프로드)은 검사하지 않는다
    d = det()
    for i in range(12):
        p = Ether(src=MY_MAC, dst="02:00:00:00:00:01") / IP(src=ME, dst=PEER) / UDP(sport=6000, dport=5000, chksum=0x1234) / Raw(b"x")
        d.observe(rec_of(p, T0 + i * 0.3))
    assert "checksum_error" not in types(d.evaluate(T0 + 6))
    # 올바른 체크섬은 알리지 않는다
    d = det()
    for i in range(30):
        d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME) / UDP(sport=5000, dport=6000) / Raw(b"ok"), T0 + i * 0.2))
    assert "checksum_error" not in types(d.evaluate(T0 + 7))


# ─────────────── TCP 주입 ───────────────
def _flow(d, n=8, ttl=52, start_seq=1000, t=T0):
    seq = start_seq
    for i in range(n):
        p = eth_in() / IP(src=PEER, dst=ME, ttl=ttl) / TCP(sport=443, dport=50000, flags="PA", seq=seq, ack=1) / Raw(b"y" * 100)
        d.observe(rec_of(p, t + i * 0.1))
        seq += 100
    return seq


def test_injected_rst_with_wrong_ttl_and_seq_is_flagged():
    d = det()
    nxt = _flow(d)
    # 경로 위 장비가 보낸 RST: TTL 이 다르고(40 vs 52), 순서 번호도 엉뚱함
    d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME, ttl=40) / TCP(sport=443, dport=50000, flags="R", seq=(nxt + 900_000_000) % (1 << 32)), T0 + 1))
    hit = [a for a in d.evaluate(T0 + 3) if a["type"] == "tcp_injection"]
    assert hit and set(hit[0]["evidence"]["indicators"]) >= {"rst_ttl", "rst_seq"}
    assert "주입" in explain(hit[0], {"local_ips": {ME}})["title"]


def test_data_after_rst_and_ttl_mismatch_data():
    d = det()
    nxt = _flow(d)
    d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME, ttl=52) / TCP(sport=443, dport=50000, flags="R", seq=nxt), T0 + 1))
    d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME, ttl=52) / TCP(sport=443, dport=50000, flags="PA", seq=nxt) / Raw(b"z" * 50), T0 + 1.2))
    d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME, ttl=60) / TCP(sport=443, dport=50000, flags="PA", seq=nxt + 50) / Raw(b"evil"), T0 + 1.3))
    hit = [a for a in d.evaluate(T0 + 3) if a["type"] == "tcp_injection"]
    assert hit and set(hit[0]["evidence"]["indicators"]) >= {"data_after_rst", "data_ttl"}


def test_normal_close_is_not_injection():
    d = det()
    nxt = _flow(d)
    d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME, ttl=52) / TCP(sport=443, dport=50000, flags="FA", seq=nxt, ack=1), T0 + 1))
    d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME, ttl=52) / TCP(sport=443, dport=50000, flags="R", seq=nxt + 1), T0 + 1.1))
    # 다른 연결의 정상 RST (닫힌 포트 응답, 상태 없음)
    d.observe(rec_of(eth_in() / IP(src="198.51.100.4", dst=ME, ttl=50) / TCP(sport=80, dport=50001, flags="RA", seq=0), T0 + 1.2))
    assert "tcp_injection" not in types(d.evaluate(T0 + 3))


# ─────────────── UDP 재전송 ───────────────
def rtp(seq, ts, ssrc=0xABCD1234, pt=0):
    return struct.pack("!BBHII", 0x80, pt, seq, ts, ssrc) + b"\x00" * 160


def test_rtp_replay_detected_and_normal_stream_quiet():
    d = det()
    for i in range(50):
        d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME) / UDP(sport=40000, dport=40002) / Raw(rtp(i, i * 160)), T0 + i * 0.02))
    assert "udp_replay" not in types(d.evaluate(T0 + 2))
    for i in range(10, 18):              # 녹음해 둔 패킷 8개를 다시 보냄
        d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME) / UDP(sport=40000, dport=40002) / Raw(rtp(i, i * 160)), T0 + 2 + i * 0.01))
    hit = [a for a in d.evaluate(T0 + 4) if a["type"] == "udp_replay"]
    assert hit and hit[0]["evidence"]["protocol"] == "RTP" and hit[0]["evidence"]["duplicates"] == 8
    assert "재전송" in explain(hit[0], {"local_ips": {ME}})["title"]


def test_configured_sequence_protocol_for_team_udp_server():
    """팀 UDP 서버처럼 페이로드 앞 4바이트에 순서 번호를 넣는 프로토콜 (설정 '9999:0:4')."""
    d = det(udp_seq_ports=["9999:0:4"])
    for i in range(20):
        d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME) / UDP(sport=50555, dport=9999) / Raw(struct.pack("!I", i) + b"cmd"), T0 + i * 0.1))
    for i in (3, 3, 4, 5, 6, 7):
        d.observe(rec_of(eth_in() / IP(src=PEER, dst=ME) / UDP(sport=50555, dport=9999) / Raw(struct.pack("!I", i) + b"cmd"), T0 + 2.5))
    hit = [a for a in d.evaluate(T0 + 4) if a["type"] == "udp_replay"]
    assert hit and hit[0]["evidence"]["protocol"] == "설정 프로토콜" and hit[0]["measured"] == 6
    assert parse_seq_ports(["9999:0:4", "bad", "70000:0:4", "1:14:4"]) == {9999: (0, 4)}


def test_new_rules_in_catalog_with_thresholds():
    rs = {r["type"]: r for r in rule_catalog(DetectionConfig())}
    for t in ("checksum_error", "tcp_injection", "udp_replay"):
        assert rs[t]["certainty"] == "suspected" and rs[t]["category_label"] == "패킷 무결성"
    assert "5" in rs["checksum_error"]["condition"]
