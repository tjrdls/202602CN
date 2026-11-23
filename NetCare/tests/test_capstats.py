"""캡처 단계별 통계(capstats)와 메모리 진단 API 테스트. 실제 인터페이스는 열지 않는다(가짜 소켓)."""
import socket
import struct

from fastapi.testclient import TestClient

from netcare.capture import capstats


class FakeBpf:
    """macOS BPF 소켓처럼 열린 뒤 누적값을 돌려줌."""
    def __init__(self):
        self.recv, self.drop = 100, 3

    def get_stats(self):
        return self.recv, self.drop


class FakeAfPacketSock:
    """Linux AF_PACKET: PACKET_STATISTICS 는 읽을 때마다 0 으로 초기화된다."""
    def __init__(self):
        self.pending = [(50, 0), (70, 5), (0, 0)]

    def getsockopt(self, level, opt, size):
        assert (level, opt, size) == (capstats.SOL_PACKET, capstats.PACKET_STATISTICS, 8)
        return struct.pack("II", *self.pending.pop(0))


def test_bpf_counter_and_sampler_deltas(monkeypatch):
    monkeypatch.setattr(capstats, "nic_counters", lambda iface: None)
    sock = FakeBpf()
    k = capstats.KernelCounter(sock)
    k.kind = "bpf"
    smp = capstats.CaptureStatsSampler(k, "en0")
    sock.recv, sock.drop = 1100, 3
    r1 = smp.sample(captured=1000, processed=990, app_dropped=0, queue_len=10)
    assert (r1["kernel_recv"], r1["kernel_drop"]) == (1000, 0)
    sock.recv, sock.drop = 2100, 13
    r2 = smp.sample(captured=1990, processed=1990, app_dropped=2, queue_len=0)
    assert (r2["kernel_recv"], r2["kernel_drop"], r2["d_kernel_drop"], r2["d_app_dropped"]) == (2000, 10, 10, 2)
    assert r2["nic_rx_dropped"] is None                     # 측정 불가 값은 채우지 않음


def test_af_packet_counter_accumulates_reset_on_read():
    class S:
        ins = FakeAfPacketSock()
    k = capstats.KernelCounter(S())
    k.kind = "af_packet"
    assert k.read() == {"recv": 50, "drop": 0, "ifdrop": None}
    assert k.read() == {"recv": 120, "drop": 5, "ifdrop": None}
    assert k.read() == {"recv": 120, "drop": 5, "ifdrop": None}


def test_unsupported_socket_reports_none():
    k = capstats.KernelCounter(object())
    assert k.kind == "unknown" and k.read() is None
    smp = capstats.CaptureStatsSampler(k, None)
    r = smp.sample(5, 5, 0, 0)
    assert r["kernel_recv"] is None and r["kernel_drop"] is None and r["nic_rx_dropped"] is None


def test_support_table_and_nic_counters_shape():
    t = capstats.support_table()
    assert t["app"] is True and isinstance(t["notes"], str)
    name = next(iter(__import__("psutil").net_io_counters(pernic=True)))
    n = capstats.nic_counters(name)
    assert n is None or {"rx_packets", "rx_dropped", "rx_errors"} <= set(n)


def test_status_and_api_expose_capture_and_memory(tmp_path):
    from netcare.api.server import create_app
    app = create_app(tmp_path, start_probe=False)
    with TestClient(app) as c:
        st = c.get("/api/status").json()
        assert "captured" in st and "capture" in st and st["capture_support"]["app"] is True
        cs = c.get("/api/capture/stats").json()
        assert cs["latest"] is None and "support" in cs
        mem = c.get("/api/diag/memory").json()
        assert "objects" in mem and mem["objects"].get("engine.queue") == 0
        # 세션에 저장된 기록 조회
        eng = app.state.engine
        sid = app.state.db.create_session("live", "x", "", "t")
        app.state.db.insert_capture_stats(sid, {"ts": 1.0, "app_captured": 3})
        assert c.get(f"/api/capture/stats?session_id={sid}").json()["history"][0]["app_captured"] == 3
        assert eng.captured == 0


def test_raw_recv_backs_off_when_interface_reads_keep_failing(monkeypatch):
    """인터페이스가 사라져 빈 읽기가 이어지면 잠깐 쉰다 (CPU 100% 헛돌기 방지)."""
    slept = []
    monkeypatch.setattr(capstats.time, "sleep", lambda s: slept.append(s))

    class Dead:
        def recv_raw(self, x=0):
            return None, None, None
    s = capstats.use_raw_frames(Dead())
    for _ in range(120):
        assert s.recv() is None
    assert len(slept) == 71 and slept[0] == 0.05

    class Live:
        def recv_raw(self, x=0):
            return bytes, b"\x00" * 60, 1.0
    f = capstats.use_raw_frames(Live()).recv()
    assert isinstance(f, capstats.RawFrame) and len(f) == 60


def test_engine_stops_capture_when_interface_disappears(tmp_path, monkeypatch):
    from netcare.capture.engine import Engine
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    eng = Engine(ConfigStore(tmp_path / "c.json"), Database(tmp_path / "t.db"), run_probe=False)
    try:
        eng._begin("live", "en9", "", "t", local_ips={"10.0.0.2"}, local_macs=set())
        eng.state = "capturing"
        eng._iface_watch, eng._iface_bad = "en9", 0
        states = iter([True, False, False])
        monkeypatch.setattr(capstats, "iface_state", lambda name: next(states))
        eng._check_iface()
        assert eng.state == "capturing"
        eng._check_iface()
        assert eng.state == "capturing"            # 한 번 끊김은 기다림
        eng._check_iface()
        assert eng.state == "error" and eng.error["code"] == "iface_lost" and "en9" in eng.error["message"]
        # 시작 때 OS 목록에서 확인하지 못한 이름이면 판단하지 않음
        eng.state, eng._iface_watch = "capturing", None
        monkeypatch.setattr(capstats, "iface_state", lambda name: False)
        eng._check_iface()
        assert eng.state == "capturing"
    finally:
        eng.state = "idle"
        eng.shutdown()


def test_queue_is_bounded_and_overflow_is_counted(tmp_path):
    """큐 상한을 넘는 유입: 큐는 상한에서 멈추고, 넘친 패킷은 '응용 단계 누락'으로 정확히 센다."""
    import queue
    from netcare.capture.engine import Engine
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    eng = Engine(ConfigStore(tmp_path / "c.json"), Database(tmp_path / "t.db"), run_probe=False)
    eng._stop.set()                                  # 처리 스레드를 멈춰 큐가 비워지지 않게 함
    for t in eng._threads:
        t.join(timeout=3)
    eng.queue = queue.Queue(maxsize=100)
    frame = capstats.RawFrame(bytes, b"\x00" * 60, 1.0)
    for _ in range(150):
        eng._enqueue_live(frame)
    assert eng.queue.qsize() == 100 and eng.dropped == 50 and eng.captured == 150
    eng.db.close()


def test_enlarge_rcvbuf_only_for_af_packet(monkeypatch):
    calls = []

    class Ins:
        def setsockopt(self, level, opt, val):
            calls.append((opt, val))
            if opt == getattr(socket, "SO_RCVBUFFORCE", 33):
                raise PermissionError("no CAP_NET_ADMIN")

        def getsockopt(self, level, opt):
            return 425984

    class S:
        ins = Ins()
    monkeypatch.setattr(capstats, "socket_kind", lambda s: "af_packet")
    assert capstats.enlarge_rcvbuf(S()) == 425984
    assert calls[-1] == (socket.SO_RCVBUF, capstats.RCVBUF_BYTES)        # 권한 없으면 일반 SO_RCVBUF 로
    monkeypatch.setattr(capstats, "socket_kind", lambda s: "bpf")
    assert capstats.enlarge_rcvbuf(S()) is None


def test_iterative_bpf_extraction_matches_scapy_original():
    """BPF 버퍼에서 프레임을 꺼내는 반복문 버전이 Scapy 원본(재귀)과 같은 결과를 내는지 (프레임·타임스탬프·정렬)."""
    import ctypes
    import pytest
    ss = pytest.importorskip("scapy.arch.bpf.supersocket")
    rng = __import__("random").Random(5)

    def hdr(sec, usec, caplen, datalen):
        h = ss.bpf_hdr()
        h.bh_tstamp.tv_sec = sec
        if hasattr(h.bh_tstamp, "tv_usec"):
            h.bh_tstamp.tv_usec = usec
        else:
            h.bh_tstamp.tv_nsec = usec * 1000
        h.bh_caplen, h.bh_datalen, h.bh_hdrlen = caplen, datalen, ss._bpf_hdr_len
        return bytes(h)[:ss._bpf_hdr_len]
    buf = b""
    for i in range(700):                          # 원본 재귀 한도 안에서 비교
        frame = bytes(rng.getrandbits(8) for _ in range(rng.randint(42, 300)))
        rec = hdr(1_700_000_000 + i, i * 7, len(frame), len(frame)) + frame
        end = ss.L2bpfListenSocket.bpf_align(ss._bpf_hdr_len, len(frame))
        buf += rec + b"\x00" * (end - len(rec))

    class Fake:
        guessed_cls = bytes
        bpf_align = staticmethod(ss.L2bpfListenSocket.bpf_align)
        extract_frames = ss.L2bpfListenSocket.extract_frames
    orig = Fake()
    orig.received_frames = []
    orig.extract_frames(buf)
    mine = Fake()
    capstats._iterative_bpf_frames(mine)
    mine.extract_frames(buf)
    got = [mine.get_frame() for _ in range(mine.buffered_frames())]
    assert got == orig.received_frames and len(got) == 700
    assert mine.get_frame() == (None, None, None)
    big = Fake()                                   # 원본은 재귀 한도를 넘는 크기도 처리
    capstats._iterative_bpf_frames(big)
    big.extract_frames(buf * 12)
    assert big.buffered_frames() == 8400
    del ctypes
