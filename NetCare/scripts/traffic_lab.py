"""트래픽 실험 도구 — 내 컴퓨터 내부(127.0.0.1)에서만 동작한다.

실제 패킷을 만들어 NetCare 의 실시간 캡처(lo0 / lo 인터페이스)와 탐지를 검증하기 위한 도구다.
대상 주소는 루프백으로 고정되어 있어 다른 장치나 외부 네트워크에는 어떤 패킷도 보내지 않는다.

    python scripts/traffic_lab.py scan      # 닫힌 포트 여러 개에 연결 시도 → 포트 스캔 / SYN 급증 탐지 실험
    python scripts/traffic_lab.py repeat    # 같은 닫힌 포트에 반복 연결 → 반복 연결 탐지 실험
    python scripts/traffic_lab.py udp       # UDP 대량 전송 → 과다 패킷 탐지 실험
    python scripts/traffic_lab.py bulk      # 로컬 TCP 서버로 대용량 전송 → 트래픽 급증 + 오탐 완화(양방향) 실험
    python scripts/traffic_lab.py normal    # 정상 TCP 연결 여러 개 → 오탐이 없어야 함
"""
from __future__ import annotations

import argparse
import socket
import threading
import time

TARGET = "127.0.0.1"  # 변경 불가: 루프백 전용


def _closed_port() -> int:
    s = socket.socket()
    s.bind((TARGET, 0))
    port = s.getsockname()[1]
    s.close()  # 바로 닫아서 '닫힌 포트'로 만든다
    return port


def scan(count: int, delay: float):
    """서로 다른 포트에 연결 시도. 열린 포트가 아니면 커널이 RST 로 거부한다."""
    tried = refused = 0
    base = 20000
    for i in range(count):
        port = base + i
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect((TARGET, port))
        except (ConnectionRefusedError, socket.timeout, OSError):
            refused += 1
        finally:
            s.close()
        tried += 1
        time.sleep(delay)
    print(f"scan: {tried}개 포트 시도, {refused}개 거부됨")


def repeat(count: int, delay: float):
    port = _closed_port()
    refused = 0
    for _ in range(count):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect((TARGET, port))
        except (ConnectionRefusedError, socket.timeout, OSError):
            refused += 1
        finally:
            s.close()
        time.sleep(delay)
    print(f"repeat: 포트 {port} 에 {count}회 시도, {refused}회 거부")


def udp(seconds: float, pps: int):
    port = _closed_port()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"x" * 200
    end, sent = time.time() + seconds, 0
    interval = 1.0 / pps
    nxt = time.time()
    while time.time() < end:
        try:
            s.sendto(payload, (TARGET, port))
            sent += 1
        except OSError:
            pass
        nxt += interval
        d = nxt - time.time()
        if d > 0:
            time.sleep(d)
    s.close()
    print(f"udp: {seconds:g}초 동안 {sent}개 전송 (목표 {pps}/s)")


def bulk(seconds: float, mbps: float):
    srv = socket.socket()
    srv.bind((TARGET, 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = [0]

    def server():
        conn, _ = srv.accept()
        while True:
            data = conn.recv(65536)
            if not data:
                break
            received[0] += len(data)
        conn.close()
    t = threading.Thread(target=server, daemon=True)
    t.start()
    c = socket.socket()
    c.connect((TARGET, port))
    chunk = b"y" * 16384
    rate = mbps * 1_000_000 / 8
    end = time.time() + seconds
    sent, t0 = 0, time.time()
    while time.time() < end:
        c.sendall(chunk)
        sent += len(chunk)
        ahead = sent / rate - (time.time() - t0)
        if ahead > 0:
            time.sleep(ahead)
    c.close()
    t.join(timeout=3)
    srv.close()
    print(f"bulk: {sent / 1e6:.1f}MB 전송 ({sent * 8 / 1e6 / seconds:.0f} Mbps)")


def normal(count: int):
    srv = socket.socket()
    srv.bind((TARGET, 0))
    srv.listen(50)
    port = srv.getsockname()[1]

    def server():
        for _ in range(count):
            conn, _ = srv.accept()
            conn.recv(100)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\nhello")
            conn.close()
    t = threading.Thread(target=server, daemon=True)
    t.start()
    for _ in range(count):
        c = socket.create_connection((TARGET, port))
        c.sendall(b"GET / HTTP/1.0\r\n\r\n")
        c.recv(100)
        c.close()
        time.sleep(0.05)
    t.join(timeout=3)
    srv.close()
    print(f"normal: {count}개 정상 연결 완료")


def main():
    ap = argparse.ArgumentParser(description="NetCare 루프백 트래픽 실험 도구 (127.0.0.1 전용)")
    ap.add_argument("mode", choices=["scan", "repeat", "udp", "bulk", "normal"])
    ap.add_argument("--count", type=int, default=150)
    ap.add_argument("--delay", type=float, default=0.02)
    ap.add_argument("--seconds", type=float, default=8)
    ap.add_argument("--pps", type=int, default=800)
    ap.add_argument("--mbps", type=float, default=200)
    a = ap.parse_args()
    if a.mode == "scan":
        scan(a.count, a.delay)
    elif a.mode == "repeat":
        repeat(a.count, a.delay)
    elif a.mode == "udp":
        udp(a.seconds, a.pps)
    elif a.mode == "bulk":
        bulk(a.seconds, a.mbps)
    else:
        normal(min(a.count, 40))


if __name__ == "__main__":
    main()
