"""BPF 수신 전용 프로세스(bpf_pump.py) + 엔진 쪽 수신 스레드(BpfPumpReader) 시험.

실제 BPF 장치 대신 유닉스 데이터그램 소켓을 쓴다: read() 한 번에 '버퍼 하나'가 통째로 나오는 점이 BPF 와 같다.
"""
import os
import socket
import sys
import threading
import time

import pytest

from netcare.capture import bpf_pump, capstats

BSD = sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd"))
needs_bpf = pytest.mark.skipif(not BSD, reason="BPF 는 macOS·BSD 전용 (Scapy 가 Linux 에서 불러오기를 거부)")


def _bpf_buffers(n_buffers: int, frames_per: int, seed: int = 3):
    """Scapy 와 같은 bpf_hdr 형식의 BPF 버퍼 목록과, 그 안의 (프레임, 타임스탬프) 목록."""
    import random
    ss = pytest.importorskip("scapy.arch.bpf.supersocket")
    rng = random.Random(seed)
    bufs, expect = [], []
    for b in range(n_buffers):
        buf = b""
        for i in range(frames_per):
            frame = bytes(rng.getrandbits(8) for _ in range(rng.randint(42, 200)))
            h = ss.bpf_hdr()
            h.bh_tstamp.tv_sec = 1_700_000_000 + b
            if hasattr(h.bh_tstamp, "tv_usec"):
                h.bh_tstamp.tv_usec = i * 10
            else:
                h.bh_tstamp.tv_nsec = i * 10_000
            h.bh_caplen = h.bh_datalen = len(frame)
            h.bh_hdrlen = ss._bpf_hdr_len
            rec = bytes(h)[:ss._bpf_hdr_len] + frame
            end = ss.L2bpfListenSocket.bpf_align(ss._bpf_hdr_len, len(frame))
            buf += rec + b"\x00" * (end - len(rec))
            expect.append((frame, 1_700_000_000 + b + i * 10 * 1e-6))
        bufs.append(buf)
    return bufs, expect


class _FakeSock:
    guessed_cls = bytes

    def __init__(self, fd):
        self.bpf_fd = fd


def _run_pump(bufs, monkeypatch, cap=None):
    if cap is not None:
        monkeypatch.setattr(capstats, "PUMP_CAP_BYTES", cap)
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    got, over = [], []
    rd = capstats.BpfPumpReader(_FakeSock(b.fileno()), got.append, over.append)
    rd.start()
    try:
        assert rd.running
        for buf in bufs:
            for _ in range(500):                       # 수신 쪽이 잠깐 늦으면 소켓 버퍼가 차서 ENOBUFS → 잠시 뒤 다시 보냄
                try:
                    a.send(buf)
                    break
                except OSError:
                    time.sleep(0.01)
            time.sleep(0.002)
        deadline = time.time() + 10
        while time.time() < deadline and len(got) + sum(over) < len(bufs) * 3:
            time.sleep(0.05)
    finally:
        rd.stop()
    assert not rd.thread.is_alive() and rd.proc.poll() is not None      # 수신 프로세스가 남지 않음
    a.close(); b.close()
    return rd, got, over


@needs_bpf
def test_pump_delivers_every_frame_in_order(monkeypatch):
    bufs, expect = _bpf_buffers(60, 3)                 # 버퍼 하나 < 2KB (맥 유닉스 데이터그램 기본 상한)
    rd, got, over = _run_pump(bufs, monkeypatch)
    assert over == [] and rd.exception is None
    assert [f.data for f in got] == [e[0] for e in expect]
    assert all(abs(f.time - e[1]) < 1e-6 for f, e in zip(got, expect))
    assert all(isinstance(f, capstats.RawFrame) and f.cls is bytes for f in got)


@needs_bpf
def test_pump_over_memory_cap_counts_frames_as_dropped(monkeypatch):
    bufs, expect = _bpf_buffers(40, 3)
    rd, got, over = _run_pump(bufs, monkeypatch, cap=1)   # 상한 1바이트: 모든 버퍼를 버리고 프레임 수만 보냄
    assert got == []
    assert sum(over) == len(expect) == rd.overflow_frames == 120


@needs_bpf
def test_count_frames_matches_scapy_layout():
    ss = pytest.importorskip("scapy.arch.bpf.supersocket")
    bufs, expect = _bpf_buffers(1, 25)
    h = ss.bpf_hdr
    assert bpf_pump.count_frames(bufs[0], h.bh_caplen.offset, h.bh_hdrlen.offset, h.bh_datalen.offset, ss.BPF_ALIGNMENT) == 25


def test_pump_used_only_for_bpf_and_can_be_disabled(monkeypatch):
    monkeypatch.setattr(capstats, "socket_kind", lambda s: s)
    monkeypatch.delenv("NETCARE_BPF_PUMP", raising=False)
    assert capstats.bpf_pump_supported("bpf")
    assert not capstats.bpf_pump_supported("af_packet") and not capstats.bpf_pump_supported("libpcap")
    monkeypatch.setenv("NETCARE_BPF_PUMP", "0")
    assert not capstats.bpf_pump_supported("bpf")
    monkeypatch.delenv("NETCARE_BPF_PUMP")
    monkeypatch.setattr(sys, "frozen", True, raising=False)     # PyInstaller 묶음에서는 기존 방식
    assert not capstats.bpf_pump_supported("bpf")


def test_engine_counts_pump_overflow_as_app_drop(tmp_path):
    from netcare.capture.engine import Engine
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    eng = Engine(ConfigStore(tmp_path / "c.json"), Database(tmp_path / "t.db"), run_probe=False)
    try:
        c0, d0 = eng.captured, eng.dropped
        eng._pump_overflow(7)
        assert (eng.captured - c0, eng.dropped - d0) == (7, 7)
    finally:
        eng.shutdown()
