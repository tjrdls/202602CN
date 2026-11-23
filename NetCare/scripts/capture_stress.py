"""고속 패킷 유입 스트레스 (루프백 전용 — 실제 네트워크로는 아무것도 보내지 않음).

    sudo 없이: ChmodBPF(access_bpf) 권한이 있으면 실행 가능 (macOS lo0 / Linux lo)
    python scripts/capture_stress.py --rates 2000,5000,10000,20000 --seconds 20 [--out result.json]

별도 프로세스가 127.0.0.1 의 닫힌 UDP 포트로 정해진 속도(초당 패킷)로 작은 데이터그램을 보낸다.
엔진은 루프백 인터페이스를 실시간 캡처(BPF 필터 'udp and port 47999')하고, 1초마다
응용(캡처·처리·큐 누락)·커널(BPF/AF_PACKET 수신·누락) 값과 RSS 를 기록한다.
NETCARE_RAW_FRAMES=0 으로 예전 방식(스니퍼 스레드가 Scapy 객체로 해석해 큐에 넣음)과 비교할 수 있다.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import platform
import socket
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PORT = 47999


def blaster(rate: int, seconds: float, ready, out):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"N" * 120
    ready.wait()
    t0 = time.perf_counter()
    sent = 0
    while True:
        el = time.perf_counter() - t0
        if el >= seconds:
            break
        target = int(el * rate)
        while sent < target:
            try:
                s.sendto(payload, ("127.0.0.1", PORT))
            except OSError:
                pass
            sent += 1
        time.sleep(0.0005)
    out.put(sent)


def run(rate: int, seconds: float, iface: str):
    import psutil
    from netcare.capture.engine import Engine
    from netcare.config import ConfigStore
    from netcare.storage.db import Database
    d = Path(tempfile.mkdtemp(prefix="capstress-"))
    eng = Engine(ConfigStore(d / "config.json"), Database(d / "t.db"), run_probe=False)
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    eng.start_live(iface, f"udp and port {PORT}")
    ready, q = mp.Event(), mp.Queue()
    p = mp.Process(target=blaster, args=(rate, seconds, ready, q))
    p.start()
    time.sleep(0.5)
    ready.set()
    peak_rss, peak_q, series = rss0, 0, []
    t0 = time.time()
    while p.is_alive() or time.time() - t0 < seconds + 0.5:
        time.sleep(1)
        rss = proc.memory_info().rss
        peak_rss, peak_q = max(peak_rss, rss), max(peak_q, eng.queue.qsize())
        k = eng.capture_sampler.kernel.read() if eng.capture_sampler else None
        series.append({"t": round(time.time() - t0, 1), "captured": eng.captured, "processed": eng.processed, "app_dropped": eng.dropped,
                       "queue": eng.queue.qsize(), "rss_mb": round(rss / 1e6, 1), "kernel": k})
        if not p.is_alive() and time.time() - t0 > seconds + 0.5:
            break
    sent = q.get(timeout=5)
    p.join()
    t_drain = time.time()
    while eng.queue.qsize() and time.time() - t_drain < 120:       # 남은 큐 처리 시간
        time.sleep(0.2)
    drain = round(time.time() - t_drain, 1)
    eng._sample_capture()
    last = eng.capture_history[-1] if eng.capture_history else {}
    eng.stop()
    eng.shutdown()
    res = {"rate_target": rate, "seconds": seconds, "sent": sent, "captured_app": eng.captured, "processed": eng.processed,
           "app_dropped": eng.dropped, "kernel_recv": last.get("kernel_recv"), "kernel_drop": last.get("kernel_drop"),
           "kernel_method": last.get("kernel_method"), "peak_queue": peak_q, "rss_start_mb": round(rss0 / 1e6, 1),
           "rss_peak_mb": round(peak_rss / 1e6, 1), "drain_sec": drain, "series": series,
           "raw_frames": os.environ.get("NETCARE_RAW_FRAMES", "1") != "0"}
    res["loss_total"] = sent - eng.processed if sent else None
    print(f"rate={rate:>6}/s sent={sent:>7} kernel_recv={res['kernel_recv']} kernel_drop={res['kernel_drop']} "
          f"app_captured={eng.captured} app_drop={eng.dropped} processed={eng.processed} peakQ={peak_q} "
          f"RSS {res['rss_start_mb']}→peak {res['rss_peak_mb']}MB drain={drain}s", flush=True)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rates", default="2000,5000,10000,20000")
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--iface", default="lo0" if platform.system() == "Darwin" else "lo")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    out = [run(int(r), a.seconds, a.iface) for r in a.rates.split(",")]
    if a.out:
        Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
