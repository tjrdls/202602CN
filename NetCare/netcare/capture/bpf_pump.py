"""BPF 수신 전용 프로세스 (macOS/BSD). NetCare 엔진이 직접 실행한다 — 사람이 실행하는 스크립트가 아니다.

    python bpf_pump.py <bpf_fd> <read_size> <cap_bytes> <hdr_caplen_off> <hdr_hdrlen_off> <hdr_datalen_off> <align>

왜 별도 프로세스인가 (2026-11-25 유선 en5 실측, docs/benchmark/stability/macos_drop_analysis):
- 512KB BPF 버퍼는 1Gbps 순간 유입에서 약 4ms 만에 찬다.
- 같은 프로세스의 수신 스레드는 처리 스레드와 파이썬 GIL 을 나눠 쓰므로 그 안에 돌아오지 못할 때가 있었다.
  같은 버퍼의 tcpdump 는 누락 0, NetCare 는 누락. 스레드 방식·전환 간격 조정으로는 결과가 8~1,012개로 흔들렸다.
- 이 프로세스는 해석·탐지를 하지 않고 BPF 버퍼를 읽어 표준 출력으로 넘기기만 한다(GIL 경쟁 없음).
  엔진이 잠깐 늦어도 데이터는 커널 버퍼가 아니라 이 프로세스의 메모리(상한 cap_bytes)에서 기다린다.

출력 형식: [4바이트 길이(little endian)][BPF 버퍼 그대로] 반복.
길이가 0xFFFFFFFF 이면 뒤의 4바이트는 '메모리 상한을 넘어 버린 프레임 수'다(엔진이 응용 단계 누락으로 센다).
Scapy·NetCare 를 import 하지 않는다 (가볍게 뜨도록).
"""
from __future__ import annotations

import collections
import errno
import os
import select
import struct
import sys
import threading
import time

OVERFLOW = 0xFFFFFFFF


def count_frames(buf: bytes, cap_off: int, hdr_off: int, dlen_off: int, align: int) -> int:
    n, off, k = len(buf), 0, 0
    while n - off >= 20:
        caplen = struct.unpack_from("<I", buf, off + cap_off)[0]
        if struct.unpack_from("<I", buf, off + dlen_off)[0] == 0:
            break
        hl = struct.unpack_from("<H", buf, off + hdr_off)[0]
        k += 1
        off += (hl + caplen + align - 1) & ~(align - 1)
    return k


def main(argv: list[str]) -> int:
    fd, size, cap, cap_off, hdr_off, dlen_off, align = (int(x) for x in argv[1:8])
    out = sys.stdout.fileno()
    q: collections.deque = collections.deque()
    cond = threading.Condition()
    state = {"bytes": 0, "dead": False}
    parent = os.getppid()

    def writer():
        try:
            while True:
                with cond:
                    while not q:
                        cond.wait()
                    item = q.popleft()
                    state["bytes"] -= len(item)
                mv = memoryview(item)
                while mv:
                    mv = mv[os.write(out, mv):]
        except OSError:                       # 엔진이 파이프를 닫음 (캡처 종료)
            pass
        state["dead"] = True

    threading.Thread(target=writer, daemon=True).start()
    empty = 0
    while not state["dead"]:
        if os.getppid() != parent:            # 엔진 프로세스가 사라짐
            break
        try:
            r, _, _ = select.select([fd], [], [], 0.5)
        except (OSError, ValueError):
            break
        if not r:
            continue
        try:
            buf = os.read(fd, size)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EINTR):
                continue
            if e.errno == errno.EBADF:
                break
            buf = b""
        if not buf:
            # 인터페이스가 사라지면 select 는 계속 '읽을 수 있음', read 는 실패 → 잠깐 쉰다 (헛돌지 않게)
            empty += 1
            if empty >= 50:
                time.sleep(0.05)
            continue
        empty = 0
        with cond:
            if state["bytes"] + len(buf) > cap:
                item = struct.pack("<II", OVERFLOW, count_frames(buf, cap_off, hdr_off, dlen_off, align))
            else:
                item = struct.pack("<I", len(buf)) + buf
            q.append(item)
            state["bytes"] += len(item)
            cond.notify()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
