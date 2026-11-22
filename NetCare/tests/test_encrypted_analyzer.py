"""암호화 통신 분석기 통합 테스트: 패킷 → parse_packet → EncryptedAnalyzer (+ 엔진·DB·API)."""
import os
import time

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from netcare.capture.parser import parse_packet
from netcare.encrypted.analyzer import EncryptedAnalyzer
from tests.test_quic import crypto, protect
from tests.tls_builders import alpn, chrome_hello, client_hello, record, server_hello, sni, versions

ME, MAC = "192.168.1.10", "02:00:00:00:01:10"
T0 = 1_700_000_000.0


def mk(src, dst, l4, payload=b"", ts=0.0):
    up = src == ME
    p = Ether(src=MAC if up else "02:00:00:00:00:01", dst="02:00:00:00:00:01" if up else MAC) / IP(src=src, dst=dst) / l4
    if payload:
        p = p / Raw(payload)
    q = p.__class__(bytes(p))
    q.time = T0 + ts
    return q


def run(pkts):
    a = EncryptedAnalyzer()
    recs = []
    for p in pkts:
        r = parse_packet(p, {ME}, {MAC})
        a.process(r, r.pop("_payload", None))
        recs.append(r)
    return a, recs


def tls_conn(server, name, cport=50000, split=True, reverse=True, ech=False, public_name=None, t=0.0):
    hello = record(chrome_hello(name, ech=ech, public_name=public_name))
    isn, sisn = 1000, 9000
    segs = [hello[:1000], hello[1000:]] if split else [hello]
    pk = [mk(ME, server, TCP(sport=cport, dport=443, flags="S", seq=isn), ts=t),
          mk(server, ME, TCP(sport=443, dport=cport, flags="SA", seq=sisn, ack=isn + 1), ts=t + 0.01)]
    data = []
    off = 0
    for sgm in segs:
        data.append(mk(ME, server, TCP(sport=cport, dport=443, flags="PA", seq=isn + 1 + off, ack=sisn + 1), sgm, ts=t + 0.02))
        off += len(sgm)
    if reverse:
        data.reverse()                                     # 뒤 조각이 먼저 도착
    pk += data
    sh = record(server_hello())
    pk.append(mk(server, ME, TCP(sport=443, dport=cport, flags="PA", seq=sisn + 1, ack=isn + 1 + off), sh, ts=t + 0.05))
    pk.append(mk(server, ME, TCP(sport=443, dport=cport, flags="PA", seq=sisn + 1 + len(sh), ack=isn + 1 + off),
                 b"\x17\x03\x03\x00\x20" + os.urandom(32), ts=t + 0.06))
    return pk


def test_tcp_split_client_hello_reordered_gets_sni_pqc_and_server_choice():
    a, recs = run(tls_conn("203.0.113.5", "news.example"))
    s = a.snapshot()
    assert s["reassembly"]["complete"] >= 2 and s["reassembly"]["multi_segment"] == 1
    assert s["sni"]["confirmed"] == 1 and s["sni"]["success_rate"] == 1.0 and s["tls_versions"]["TLS 1.3"] == 1
    assert s["pqc"] == {"offered": 1, "negotiated": 1} and s["alpn"]["h2"] == 1
    done = [r for r in recs if (r.get("enc") or {}).get("sni")]
    assert done and done[0]["enc"]["sni"]["real_sni"] == "news.example" and "reasm_multi" in done[0]["tags"]
    assert "news.example" in done[0]["friendly"] and "SNI=news.example" in done[0]["info"]
    assert "opaque" in recs[-1]["tags"] and s["opaque"]["bytes"] > 0


def test_ech_states_are_kept_apart():
    a, _ = run(tls_conn("203.0.113.6", "real.example", ech=True, public_name="cloudflare-ech.com", split=False)
               + tls_conn("203.0.113.7", "maybe.example", ech=True, split=False, cport=50001, t=1))
    s = a.snapshot()
    assert s["ech"]["confirmed"] == 1 and s["ech"]["unconfirmed"] == 1 and s["sni"]["limited"] == 1 and s["sni"]["estimated"] == 1
    evs = a.recent(kind="TLS")
    assert not any("real.example" in str(e) for e in evs)                      # 실제 도메인을 지어내지 않음


def test_missing_segment_reported_as_failed():
    pk = tls_conn("203.0.113.8", "gap.example", reverse=False)
    del pk[2]                                                                  # 첫 조각 누락
    a, _ = run(pk)
    a.tick(T0 + 30)
    s = a.snapshot()
    assert s["reassembly"]["failed"] == 1 and s["sni"]["failed"] >= 1 and s["reassembly"]["fail_reasons"]


def test_quic_http3_and_short_header_counted():
    dcid, scid = os.urandom(8), os.urandom(8)
    ch = chrome_hello("video.example", ech=False, alpns=("h3",))
    p1 = protect(crypto(0, ch[:900]), dcid, scid, pn=0, pad_to=1250)
    p2 = protect(crypto(900, ch[900:]), dcid, scid, pn=1, pad_to=1250)
    pk = [mk(ME, "198.51.100.9", UDP(sport=55000, dport=443), p1, 0), mk(ME, "198.51.100.9", UDP(sport=55000, dport=443), p2, 0.01),
          mk("198.51.100.9", ME, UDP(sport=443, dport=55000), bytes([0x41]) + os.urandom(300), 0.2)]
    a, recs = run(pk)
    s = a.snapshot()
    assert s["quic"]["http3"] == 1 and s["handshakes"]["quic"] == 1 and s["protocol_bytes"]["QUIC"] > 0
    assert recs[1]["enc"]["sni"]["real_sni"] == "video.example" and "h3" in recs[1]["tags"]
    assert "opaque" in recs[2]["tags"]


def test_dns_kinds_confirmed_vs_estimated():
    dcid, scid = os.urandom(8), os.urandom(8)
    pk = [mk(ME, "192.168.1.1", UDP(sport=5353 + 1, dport=53) / DNS(id=1, qd=DNSQR(qname="example.com")), ts=0)]
    pk += [mk(ME, "9.9.9.9", TCP(sport=40000, dport=853, flags="PA", seq=1), record(client_hello(sni("dns.quad9.net"), alpn("dot"), versions(0x0304))), 0.1)]
    doq = client_hello(sni("dns.adguard-dns.com"), alpn("doq"), versions(0x0304))
    pk += [mk(ME, "94.140.14.14", UDP(sport=41000, dport=853), protect(crypto(0, doq), dcid, scid), 0.2)]
    pk += [mk(ME, "142.250.1.1", TCP(sport=42000, dport=443, flags="PA", seq=1), record(client_hello(sni("dns.google"), alpn("h2"), versions(0x0304))), 0.3)]
    pk += [mk(ME, "1.1.1.1", TCP(sport=43000, dport=443, flags="PA", seq=1), record(client_hello(alpn("h2"), versions(0x0304))), 0.4)]
    pk += [mk(ME, "203.0.113.50", TCP(sport=44000, dport=443, flags="PA", seq=1), record(client_hello(sni("shop.example"), versions(0x0304))), 0.5)]
    a, recs = run(pk)
    d = a.snapshot()["dns"]
    assert d["flows"] == {"dns": 1, "dot": 1, "doq": 1, "doh": 2}
    assert d["confirmed_flows"]["dot"] == 1 and d["confirmed_flows"]["doq"] == 1 and d["confirmed_flows"]["doh"] == 0
    doh = {f["server"]: f for f in d["list"] if f["kind"] == "doh"}
    assert doh["142.250.1.1"]["confidence"] == "높음" and doh["1.1.1.1"]["confidence"] == "중간"
    assert "203.0.113.50" not in {f["server"] for f in d["list"]}               # 443 이라는 이유만으로 DoH 아님
    assert "domain" not in doh["142.250.1.1"]                                   # 암호화 DNS 는 질의 도메인을 표시하지 않음
    assert "dot" in recs[1]["tags"] and "doh_est" in recs[3]["tags"]


def test_engine_pcap_import_api_and_tag_filter(tmp_path):
    from fastapi.testclient import TestClient
    import netcare.config as C
    from netcare.api.server import create_app
    pkts = tls_conn("203.0.113.5", "pcap.example") + tls_conn("203.0.113.6", "x.example", ech=True, public_name="cloudflare-ech.com", cport=50002, t=1, split=False)
    path = tmp_path / "enc.pcap"
    wrpcap(str(path), pkts)
    C.DATA_DIR = tmp_path
    app = create_app(data_dir=tmp_path) if "data_dir" in create_app.__code__.co_varnames else create_app()
    with TestClient(app, base_url="http://127.0.0.1:8765") as cl:
        H = {"X-NetCare": "1"}
        with open(path, "rb") as f:
            r = cl.post("/api/capture/import", files={"file": ("enc.pcap", f, "application/vnd.tcpdump.pcap")}, headers=H)
        assert r.status_code == 200, r.text
        for _ in range(100):
            if cl.get("/api/status").json()["state"] != "importing":
                break
            time.sleep(0.05)
        s = cl.get("/api/encrypted").json()["summary"]
        assert s["sni"]["confirmed"] == 1 and s["ech"]["confirmed"] == 1 and s["reassembly"]["multi_segment"] == 1
        sid = cl.get("/api/status").json()["session"]["id"]
        tagged = cl.get(f"/api/packets?session_id={sid}&tag=sni_ok&with_total=true").json()
        assert tagged["total"] == 1 and "pcap.example" in tagged["packets"][0]["info"]
        assert cl.get(f"/api/packets?session_id={sid}&tag=ech").json()["packets"]
        ev = cl.get("/api/encrypted/events?kind=TLS").json()["events"]
        pid = next(e["packet_id"] for e in ev if e.get("sni", {}).get("real_sni") == "pcap.example")
        det = cl.get(f"/api/packets/{pid}").json()
        assert det["encrypted"]["reassembly"]["multi_segment"] and det["encrypted"]["hello"]["hybrid"]
        assert cl.get("/api/packets?tag=bad tag!").status_code == 422


def test_plain_http_connection_is_not_a_reassembly_failure():
    pk = [mk(ME, "34.223.124.45", TCP(sport=51000, dport=80, flags="S", seq=10), ts=0),
          mk(ME, "34.223.124.45", TCP(sport=51000, dport=80, flags="PA", seq=11), b"GET / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n", 0.1),
          mk(ME, "34.223.124.45", TCP(sport=51000, dport=80, flags="FA", seq=60), ts=0.2)]
    a, _ = run(pk)
    a.tick(T0 + 60)
    s = a.snapshot()
    assert s["reassembly"]["failed"] == 0 and s["sni"]["attempts"] == 0


def test_ech_public_name_learned_from_dns_https_record():
    import struct
    from scapy.layers.dns import DNSRRHTTPS, SvcParam
    from netcare.encrypted.tls_hello import LEARNED_PUBLIC_NAMES
    pn = b"cover.example-ech.net"
    c = b"\x07" + b"\x00\x20" + struct.pack("!H", 32) + b"\x01" * 32 + struct.pack("!H", 4) + b"\x00\x01\x00\x01" + b"\x00" + bytes([len(pn)]) + pn + b"\x00\x00"
    cfg = b"\xfe\x0d" + struct.pack("!H", len(c)) + c
    rr = DNSRRHTTPS(rrname="secret-site.example", svc_priority=1, target_name=".", svc_params=[SvcParam(key=5, value=struct.pack("!H", len(cfg)) + cfg)])
    dns_resp = mk("192.168.1.1", ME, UDP(sport=53, dport=5001) / DNS(id=9, qr=1, qd=DNSQR(qname="secret-site.example", qtype=65), an=rr), ts=0)
    hello = tls_conn("198.51.100.20", "secret-site.example", ech=True, public_name="cover.example-ech.net", split=False, t=0.5)
    a, recs = run([dns_resp] + hello)
    assert LEARNED_PUBLIC_NAMES.get("cover.example-ech.net") == "secret-site.example"
    ev = [e for e in a.recent(kind="TLS") if (e.get("sni") or {}).get("outer_sni")]
    assert ev and ev[0]["sni"]["ech"] == "confirmed" and ev[0]["sni"]["real_sni"] is None   # 공개 이름만, 실제 도메인은 비움
    assert a.snapshot()["ech"]["configs_seen_in_dns"] == 1


def test_friendly_text_does_not_assert_domain_when_ech_extension_present():
    a, recs = run(tls_conn("203.0.113.7", "maybe.example", ech=True, split=False))
    hello = next(r for r in recs if (r.get("enc") or {}).get("sni"))
    assert "확정할 수 없어요" in hello["friendly"] and "사이트에 암호화 연결을 시작해요" not in hello["friendly"]
