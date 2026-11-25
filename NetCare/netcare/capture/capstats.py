"""캡처 단계별 패킷 수·누락 통계 — 응용(NetCare 큐) · 커널(캡처 소켓) · NIC(인터페이스) 를 나눠 기록한다.

| 단계 | macOS | Linux | Windows (Npcap) |
|---|---|---|---|
| 커널 캡처 소켓 | BPF BIOCGSTATS: bs_recv(필터 적용 전 BPF 가 본 패킷), bs_drop(필터 통과 후 버퍼가 가득 차 버린 패킷) | AF_PACKET PACKET_STATISTICS: tp_packets(필터 통과), tp_drops(소켓 버퍼 부족으로 버림). 읽을 때마다 0 으로 초기화되므로 누적해서 기록 | pcap_stats: ps_recv, ps_drop, ps_ifdrop |
| NIC / 인터페이스 | psutil(ifi_iqdrops·ierrors) | psutil + /sys/class/net/<if>/statistics (rx_dropped·rx_missed_errors·rx_fifo_errors) | psutil(InDiscards·InErrors) |
| 응용 | NetCare 큐가 가득 차 버린 패킷 (모든 OS 동일) | | |

지원하지 않는 값은 None 으로 두고 화면·보고서에 '측정 불가'로 표시한다(추정값으로 채우지 않음).
"""
from __future__ import annotations

import ctypes
import logging
import platform
import socket
import struct
import time
from pathlib import Path

log = logging.getLogger("netcare.capstats")

SOL_PACKET = 263
PACKET_STATISTICS = 6


BPF_BUFFER_BYTES = 512 * 1024


def enlarge_bpf_buffer() -> int | None:
    """macOS/BSD BPF 버퍼를 키운다 (Scapy 기본 64KB = 1500B 패킷 약 43개 → 순간 유입 때 커널 단계 누락).

    실측(2026-11-23, Wi-Fi 1시간): 초당 약 1,200개 순간 유입 27번에서 BPF 누락 6,819개. 커널 허용 최대치
    (sysctl debug.bpf_maxbufsize, 보통 512KB)까지 올린다. BPF 는 읽기 크기가 버퍼 크기와 같아야 하므로
    use_raw_frames 의 읽기 크기도 이 값을 쓴다. 같은 프로세스의 다른 Scapy BPF 소켓(NetCare 에는 없음)에도 적용된다."""
    try:
        import scapy.arch.bpf.supersocket as ss
    except Exception:
        return None
    size = BPF_BUFFER_BYTES
    try:
        import subprocess
        mx = int(subprocess.run(["sysctl", "-n", "debug.bpf_maxbufsize"], capture_output=True, text=True, timeout=3).stdout.strip())
        size = min(size, mx)
    except Exception:
        pass
    ss.BPF_BUFFER_LENGTH = max(size, ss.BPF_BUFFER_LENGTH)
    return ss.BPF_BUFFER_LENGTH


def open_listen_socket(cap_iface, bpf: str | None, promisc: bool, big_bpf: bool = False):
    """Scapy sniff() 가 내부에서 여는 것과 같은 수신 소켓. 직접 열어야 커널 통계를 읽을 수 있다.
    big_bpf: macOS/BSD 에서 BPF 버퍼를 키움 (use_raw_frames 와 함께 쓸 때만 — 읽기 크기를 맞추기 때문)."""
    from scapy.data import ETH_P_ALL
    from scapy.interfaces import resolve_iface
    if big_bpf and platform.system() in ("Darwin", "FreeBSD", "OpenBSD", "NetBSD"):
        enlarge_bpf_buffer()
    sock = resolve_iface(cap_iface).l2listen()(type=ETH_P_ALL, iface=cap_iface, filter=bpf or None, promisc=promisc)
    enlarge_rcvbuf(sock)
    return sock


RCVBUF_BYTES = 8 * 1024 * 1024


def enlarge_rcvbuf(sock) -> int | None:
    """Linux AF_PACKET 수신 버퍼를 키운다. Scapy 기본값(conf.bufsize)은 64KB 라서 순간 유입 때 커널 단계 누락이 컸다
    (CI 실측: Ubuntu lo 초당 1만 개에서 커널 누락 67,005개). 권한이 있으면 SO_RCVBUFFORCE, 없으면 net.core.rmem_max 까지.
    적용된 크기(바이트)를 돌려준다. macOS BPF·Npcap 은 해당 없음(None)."""
    if socket_kind(sock) != "af_packet":
        return None
    s = sock.ins
    for opt in (getattr(socket, "SO_RCVBUFFORCE", 33), socket.SO_RCVBUF):
        try:
            s.setsockopt(socket.SOL_SOCKET, opt, RCVBUF_BYTES)
            break
        except OSError:
            continue
    try:
        return s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    except OSError:
        return None


class RawFrame:
    """스니퍼 스레드가 큐에 넣는 원시 프레임 (해석은 처리 스레드가 한 번만 한다).

    예전에는 Scapy 가 스니퍼 스레드에서 모든 패킷을 Packet 객체로 해석한 뒤 큐에 넣었다. 큐 상한 50,000개가
    Packet 객체로 차면 실측 RSS 가 약 1GB 까지 올랐고(2026-11-23 고속 유입), 해석 비용 때문에 스니퍼가
    커널 버퍼를 늦게 비워 커널 단계 누락도 커졌다. 원시 바이트만 넣으면 큐 메모리가 패킷 크기 수준으로 줄어든다.
    """
    __slots__ = ("cls", "data", "time", "sniffed_on")

    def __init__(self, cls, data: bytes, ts):
        self.cls, self.data, self.time, self.sniffed_on = cls, data, ts, None

    def __len__(self):
        return len(self.data)

    def dissect(self):
        from scapy.config import conf
        try:
            pkt = self.cls(self.data)
        except Exception:                      # Scapy SuperSocket.recv 와 같은 처리: 해석 실패는 Raw 로
            pkt = conf.raw_layer(self.data)
        if self.time:
            pkt.time = self.time
        return pkt


def use_raw_frames(sock):
    """소켓의 recv() 를 '해석하지 않고 RawFrame 을 돌려주는' 버전으로 바꾼다 (select·recv_raw 는 그대로)."""
    from scapy.data import MTU
    empty = [0]
    is_bpf = socket_kind(sock) == "bpf"
    if is_bpf:
        _iterative_bpf_frames(sock)
    raw_recv = sock.recv_raw

    def recv(x=MTU, **_kw):
        if is_bpf:                          # BPF 는 버퍼 크기 그대로 읽어야 함 (버퍼 안에 프레임 여러 개)
            import scapy.arch.bpf.supersocket as ss
            x = ss.BPF_BUFFER_LENGTH
        cls, val, ts = raw_recv(x)
        if not val or not cls:
            # 인터페이스가 사라지면(USB 랜 분리 등) select 는 계속 '읽을 수 있음'을 돌려주고 read 는 실패해 CPU 100% 로 헛돈다
            # (실측 2026-11-23: en5 분리 뒤 수정 전·후 서버 모두 3시간 넘게 CPU 100%). 빈 읽기가 이어지면 잠깐 쉰다.
            empty[0] += 1
            if empty[0] >= 50:
                time.sleep(0.05)
            return None
        empty[0] = 0
        return RawFrame(cls, val, ts)
    sock.recv = recv
    return sock


def _iterative_bpf_frames(sock):
    """Scapy BPF 소켓의 프레임 꺼내기를 반복문으로 바꾼다 (동작은 같음: 같은 헤더·정렬·종료 조건).

    Scapy 원본 extract_frames 는 프레임마다 재귀하며 남은 버퍼를 복사하고(O(n²)), get_frame 은 list.pop(0) 이다.
    BPF 버퍼를 512KB 로 키우면 작은 패킷 수천 개가 한 번에 들어와 재귀 한도를 넘었다
    (루프백 초당 6만 개 시험: 캡처 사실상 중단, RSS 531MB)."""
    from collections import deque

    import scapy.arch.bpf.supersocket as ss
    frames: deque = deque()
    hl = ss._bpf_hdr_len
    nano = getattr(ss, "_NANOTIME", False)

    def extract_frames(buf):
        n, off, first = len(buf), 0, True
        cls = sock.guessed_cls
        while n - off >= hl and (first or n - off >= 20):
            first = False
            h = ss.bpf_hdr.from_buffer_copy(buf, off)
            if h.bh_datalen == 0:
                break
            st = off + h.bh_hdrlen
            ts = h.bh_tstamp.tv_sec + (1e-9 * h.bh_tstamp.tv_nsec if nano else 1e-6 * h.bh_tstamp.tv_usec)
            frames.append((cls, buf[st:st + h.bh_caplen], ts))
            off += ss.L2bpfListenSocket.bpf_align(h.bh_hdrlen, h.bh_caplen)

    def get_frame():
        return frames.popleft() if frames else (None, None, None)

    sock.received_frames = frames
    sock.extract_frames = extract_frames
    sock.get_frame = get_frame
    sock.buffered_frames = lambda: len(frames)


PUMP_CAP_BYTES = 256 * 1024 * 1024     # 수신 프로세스가 엔진 대신 들고 있을 수 있는 최대 바이트 (넘으면 버리고 개수를 센다)


def bpf_pump_supported(sock) -> bool:
    """수신 전용 프로세스를 쓸 수 있는가: macOS/BSD BPF 소켓, 파이썬으로 실행 중(PyInstaller 묶음 아님), 환경변수로 끄지 않음."""
    import os
    import sys
    return (socket_kind(sock) == "bpf" and not getattr(sys, "frozen", False)
            and os.environ.get("NETCARE_BPF_PUMP", "1") != "0")


class BpfPumpReader:
    """macOS/BSD: BPF 를 별도 프로세스(bpf_pump.py)가 읽고, 이 스레드는 파이프에서 받아 프레임으로 잘라 콜백에 넘긴다.

    같은 프로세스 수신 스레드는 처리 스레드와 GIL 을 나눠 써서, 1Gbps 순간 유입 때 512KB BPF 버퍼(약 4ms 분량)를
    제때 비우지 못했다(유선 실측: tcpdump 0, NetCare 누락). 수신 프로세스는 GIL 경쟁이 없어 커널 버퍼를 바로 비우고,
    엔진이 늦으면 데이터는 그 프로세스 메모리(상한 PUMP_CAP_BYTES)에서 기다린다. 상한을 넘겨 버린 프레임은
    응용 단계 누락으로 센다(on_overflow). 커널 통계는 같은 BPF 장치를 공유하므로 엔진 쪽 소켓에서 그대로 읽는다.
    AsyncSniffer 와 같은 속성(start·stop·running·exception)을 가진다."""

    def __init__(self, sock, prn, on_overflow=None):
        import threading
        self.sock, self.prn, self.on_overflow = sock, prn, on_overflow
        self.exception = None
        self.proc = None
        self._stop = threading.Event()
        self._running = False
        self.overflow_frames = 0
        self.thread = threading.Thread(target=self._run, name="netcare-bpf-pump", daemon=True)

    @property
    def running(self) -> bool:
        return self._running

    def start(self):
        import subprocess
        import sys

        import scapy.arch.bpf.supersocket as ss
        h = ss.bpf_hdr
        fd = self.sock.bpf_fd
        args = [sys.executable, "-I", str(Path(__file__).with_name("bpf_pump.py")), str(fd), str(ss.BPF_BUFFER_LENGTH),
                str(PUMP_CAP_BYTES), str(h.bh_caplen.offset), str(h.bh_hdrlen.offset), str(h.bh_datalen.offset),
                str(ss.BPF_ALIGNMENT)]
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, pass_fds=(fd,), bufsize=0)
        self._running = True
        self.thread.start()

    def stop(self, join: bool = True):
        self._stop.set()
        p = self.proc
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()
        if join and self.thread.is_alive():
            self.thread.join(timeout=3)

    def _run(self):
        import os
        import select

        import scapy.arch.bpf.supersocket as ss
        hl, nano = ss._bpf_hdr_len, getattr(ss, "_NANOTIME", False)
        hdr, align = ss.bpf_hdr.from_buffer_copy, ss.L2bpfListenSocket.bpf_align
        prn, stop = self.prn, self._stop
        pfd = self.proc.stdout.fileno()
        pending = bytearray()
        try:
            while not stop.is_set():
                r, _, _ = select.select([pfd], [], [], 0.5)
                if not r:
                    if self.proc.poll() is not None:
                        break
                    continue
                chunk = os.read(pfd, 4 * 1024 * 1024)
                if not chunk:                                  # 수신 프로세스가 끝남
                    break
                pending += chunk
                pos = 0
                while True:
                    avail = len(pending) - pos
                    if avail < 4:
                        break
                    ln = int.from_bytes(pending[pos:pos + 4], "little")
                    if ln == 0xFFFFFFFF:                       # 수신 프로세스가 상한을 넘어 버린 프레임 수
                        if avail < 8:
                            break
                        k = int.from_bytes(pending[pos + 4:pos + 8], "little")
                        self.overflow_frames += k
                        if self.on_overflow:
                            self.on_overflow(k)
                        pos += 8
                        continue
                    if avail - 4 < ln:
                        break
                    buf = bytes(pending[pos + 4:pos + 4 + ln])
                    pos += 4 + ln
                    cls = self.sock.guessed_cls
                    n, off, first = len(buf), 0, True
                    while n - off >= hl and (first or n - off >= 20):
                        first = False
                        h = hdr(buf, off)
                        if h.bh_datalen == 0:
                            break
                        st = off + h.bh_hdrlen
                        ts = h.bh_tstamp.tv_sec + (1e-9 * h.bh_tstamp.tv_nsec if nano else 1e-6 * h.bh_tstamp.tv_usec)
                        prn(RawFrame(cls, buf[st:st + h.bh_caplen], ts))
                        off += align(h.bh_hdrlen, h.bh_caplen)
                if pos:
                    del pending[:pos]
            if not stop.is_set() and self.proc.poll() is not None and self.proc.returncode not in (0, None):
                self.exception = RuntimeError(f"BPF 수신 프로세스가 종료됨 (코드 {self.proc.returncode})")
        except Exception as e:                             # AsyncSniffer 처럼 예외를 보관하고 멈춘다 (엔진이 감지)
            self.exception = e
            log.exception("BPF pump reader failed")
        finally:
            self._running = False
            try:
                self.proc.stdout.close()
            except Exception:
                pass


def iface_state(name: str | None) -> bool | None:
    """인터페이스가 있고 켜져 있으면 True, 없거나 꺼졌으면 False, 확인할 수 없으면 None."""
    if not name:
        return None
    try:
        import psutil
        st = psutil.net_if_stats()
    except Exception:
        return None
    if name not in st:
        return False
    return bool(st[name].isup)


def socket_kind(sock) -> str:
    name = type(sock).__name__
    if hasattr(sock, "pcap_fd") and hasattr(getattr(sock, "pcap_fd"), "pcap"):
        return "libpcap"
    if "bpf" in name.lower() and hasattr(sock, "get_stats"):
        return "bpf"
    if platform.system() == "Linux" and isinstance(getattr(sock, "ins", None), socket.socket):
        return "af_packet"
    return "unknown"


class KernelCounter:
    """캡처 소켓의 누적 수신/누락 카운터. 지원하지 않으면 read() 가 None 을 돌려준다."""

    def __init__(self, sock):
        self.sock = sock
        self.kind = socket_kind(sock) if sock is not None else "none"
        self._lin_recv = 0      # AF_PACKET 은 읽을 때 초기화되므로 누적
        self._lin_drop = 0
        self.error: str | None = None

    def read(self) -> dict | None:
        try:
            if self.kind == "bpf":
                recv, drop = self.sock.get_stats()
                if recv is None:
                    return None
                return {"recv": int(recv), "drop": int(drop), "ifdrop": None}
            if self.kind == "af_packet":
                raw = self.sock.ins.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
                tp_packets, tp_drops = struct.unpack("II", raw)
                self._lin_recv += tp_packets
                self._lin_drop += tp_drops
                return {"recv": self._lin_recv, "drop": self._lin_drop, "ifdrop": None}
            if self.kind == "libpcap":
                from scapy.libs.winpcapy import pcap_stat, pcap_stats
                st = pcap_stat()
                if pcap_stats(self.sock.pcap_fd.pcap, ctypes.byref(st)) != 0:
                    return None
                return {"recv": int(st.ps_recv), "drop": int(st.ps_drop), "ifdrop": int(st.ps_ifdrop)}
        except Exception as e:                      # 소켓이 닫혔거나 OS 가 지원하지 않음
            self.error = str(e)[:200]
        return None


def nic_counters(iface: str | None) -> dict | None:
    if not iface:
        return None
    out: dict = {}
    try:
        import psutil
        c = psutil.net_io_counters(pernic=True).get(iface)
        if c is not None:
            out.update(rx_packets=c.packets_recv, rx_dropped=c.dropin, rx_errors=c.errin)
    except Exception:
        pass
    if platform.system() == "Linux":
        base = Path("/sys/class/net") / iface / "statistics"
        for name in ("rx_missed_errors", "rx_fifo_errors", "rx_over_errors"):
            try:
                out[name] = int((base / name).read_text().strip())
            except (OSError, ValueError):
                pass
    return out or None


def support_table() -> dict:
    """현재 OS 에서 어떤 단계의 누락을 잴 수 있는지 (화면 안내용)."""
    sysname = platform.system()
    return {
        "os": sysname,
        "app": True,
        "kernel": sysname in ("Darwin", "Linux", "Windows", "FreeBSD"),
        "kernel_ifdrop": sysname == "Windows",
        "nic": True,
        "nic_extra": sysname == "Linux",
        "notes": {
            "Darwin": "커널: BPF 통계(bs_recv 는 필터 적용 전, bs_drop 은 BPF 버퍼 부족). NIC: 인터페이스 입력 누락(ifi_iqdrops). NIC 하드웨어 링 버퍼 누락은 macOS 가 제공하지 않아 측정 불가.",
            "Linux": "커널: AF_PACKET 소켓 통계(필터 통과 패킷·소켓 버퍼 부족 누락). NIC: rx_dropped·rx_missed_errors·rx_fifo_errors.",
            "Windows": "커널: Npcap pcap_stats(ps_recv·ps_drop·ps_ifdrop). NIC: InDiscards·InErrors.",
        }.get(sysname, "이 OS 의 커널 캡처 통계는 확인되지 않았어요."),
    }


class CaptureStatsSampler:
    """세션 시작 시점을 0 으로 두고 10초마다 단계별 누적·구간 값을 만든다."""

    def __init__(self, kernel: KernelCounter | None, iface: str | None):
        self.kernel = kernel
        self.iface = iface
        self.t0 = time.time()
        self.k0 = kernel.read() if kernel else None
        self.n0 = nic_counters(iface)
        self.prev: dict | None = None

    def sample(self, captured: int, processed: int, app_dropped: int, queue_len: int) -> dict:
        now = time.time()
        k = self.kernel.read() if self.kernel else None
        n = nic_counters(self.iface)
        row = {"ts": now, "elapsed": round(now - self.t0, 1), "app_captured": captured, "app_processed": processed,
               "app_dropped": app_dropped, "queue": queue_len,
               "kernel_method": self.kernel.kind if self.kernel else None,
               "kernel_recv": None, "kernel_drop": None, "kernel_ifdrop": None,
               "nic_rx_packets": None, "nic_rx_dropped": None, "nic_rx_errors": None, "nic_rx_missed": None}
        if k is not None and self.k0 is not None:
            # BPF·pcap 은 소켓을 연 뒤의 누적값 (AF_PACKET 은 KernelCounter 가 누적), 세션 시작 기준으로 뺀다
            row["kernel_recv"] = k["recv"] - self.k0["recv"]
            row["kernel_drop"] = k["drop"] - self.k0["drop"]
            if k.get("ifdrop") is not None and self.k0.get("ifdrop") is not None:
                row["kernel_ifdrop"] = k["ifdrop"] - self.k0["ifdrop"]
        if n and self.n0:
            for src, dst in (("rx_packets", "nic_rx_packets"), ("rx_dropped", "nic_rx_dropped"), ("rx_errors", "nic_rx_errors"),
                             ("rx_missed_errors", "nic_rx_missed")):
                if src in n and src in self.n0:
                    row[dst] = n[src] - self.n0[src]
        p = self.prev
        for key in ("app_captured", "app_dropped", "kernel_recv", "kernel_drop", "nic_rx_dropped"):
            cur, old = row.get(key), (p or {}).get(key)
            row["d_" + key] = (cur - old) if (cur is not None and old is not None) else None
        self.prev = row
        return row
