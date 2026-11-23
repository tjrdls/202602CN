"""OS별 실제 캡처 자가 점검 — Windows(Npcap) · Linux(AF_PACKET) · macOS(BPF) 에서 같은 명령으로 실행한다.

    python scripts/os_capture_check.py                       # 기본 경로 인터페이스 30초 + 루프백 시험
    python scripts/os_capture_check.py --iface "이더넷" --seconds 60 --out result.json

관리자 권한(Windows: 관리자 명령 프롬프트, Linux: sudo, macOS: ChmodBPF 또는 sudo)이 필요하다.
시험 중 보내는 트래픽: example.com 으로의 DNS 조회·HTTPS 접속 몇 번, 루프백(127.0.0.1) 닫힌 포트로의 UDP 뿐.

점검 항목 (각각 통과/실패/건너뜀)
 1. 환경: OS · Python · Scapy · 캡처 소켓 종류(BPF / AF_PACKET / libpcap(Npcap))
 2. 인터페이스: 목록, 화면 이름 → 캡처 장치 이름 변환, 인터페이스 상태 확인(분리 감지에 쓰임)
 3. 실제 캡처: 원시 프레임 수신, 커널 통계(수신·누락) 읽기, NIC 카운터
 4. 해석 대조: 잡은 실제 패킷마다 빠른 경로와 Scapy 경로 결과가 같은지
 5. 엔진 실캡처: NetCare 엔진으로 캡처해 응용·커널 단계 통계가 기록되는지
 6. 루프백 고속 유입: 초당 2,000 / 10,000개에서 누락 (Windows 는 Npcap 루프백 어댑터가 있을 때만)
"""
from __future__ import annotations

import argparse
import json
import platform
import socket
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RESULTS: list[dict] = []


def record(name: str, status: str, detail):
    RESULTS.append({"check": name, "status": status, "detail": detail})
    mark = {"pass": "통과", "fail": "실패", "skip": "건너뜀"}[status]
    print(f"[{mark}] {name}: {json.dumps(detail, ensure_ascii=False, default=str)[:600]}", flush=True)


def make_traffic(stop: threading.Event):
    """평범한 트래픽: DNS 조회와 HTTPS 접속 (example.com)."""
    while not stop.is_set():
        try:
            socket.getaddrinfo("example.com", 443)
            urllib.request.urlopen("https://example.com/", timeout=5).read(256)
        except Exception:
            pass
        stop.wait(2)


def pick_iface(arg: str | None) -> str | None:
    from netcare.capture import interfaces
    if arg:
        return arg
    lst = interfaces.list_interfaces()
    rec = [i for i in lst if i.get("is_default")] or [i for i in lst if i.get("is_up") and i.get("ipv4")]
    if rec:
        return rec[0]["name"]
    return lst[0]["name"] if lst else None


def loopback_name() -> str | None:
    sysname = platform.system()
    if sysname == "Darwin":
        return "lo0"
    if sysname == "Linux":
        return "lo"
    try:
        from scapy.all import conf
        for dev in conf.ifaces.values():
            if "loopback" in (getattr(dev, "description", "") or "").lower() or "loopback" in (dev.name or "").lower():
                return dev.name
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None)
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--no-loopback", action="store_true")
    ap.add_argument("--out", default="os_capture_check.json")
    a = ap.parse_args()

    # 1. 환경
    import scapy
    from scapy.all import conf  # noqa: F401  (실시간 캡처와 같은 계층 바인딩)
    env = {"os": platform.platform(), "python": sys.version.split()[0], "scapy": scapy.__version__,
           "use_pcap": bool(getattr(conf, "use_pcap", False)), "L2listen": getattr(conf.L2listen, "__name__", str(conf.L2listen))}
    record("환경", "pass", env)

    # 2. 인터페이스
    from netcare.capture import capstats, interfaces
    try:
        lst = interfaces.list_interfaces()
        iface = pick_iface(a.iface)
        cap = interfaces.resolve_capture_iface(iface) if iface else None
        state = capstats.iface_state(iface)
        ok = bool(iface) and cap is not None
        record("인터페이스", "pass" if ok else "fail", {"count": len(lst), "chosen": iface, "capture_device": str(cap), "os_state_known": state})
    except Exception as e:
        record("인터페이스", "fail", f"{type(e).__name__}: {e}")
        iface = cap = None

    stop = threading.Event()
    threading.Thread(target=make_traffic, args=(stop,), daemon=True).start()

    # 3·4. 원시 캡처 + 해석 대조
    frames = []
    if cap is not None:
        try:
            sock = capstats.use_raw_frames(capstats.open_listen_socket(cap, None, False, big_bpf=True))
            kc = capstats.KernelCounter(sock)
            k0, n0 = kc.read(), capstats.nic_counters(iface)
            t0 = time.time()
            while time.time() - t0 < min(a.seconds, 20) and len(frames) < 20000:
                f = sock.recv()
                if f is not None:
                    frames.append(f)
            k1, n1 = kc.read(), capstats.nic_counters(iface)
            rcvbuf = None
            if kc.kind == "af_packet":
                rcvbuf = sock.ins.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            sock.close()
            det = {"socket": type(sock).__name__, "kernel_method": kc.kind, "frames": len(frames), "kernel_start": k0, "kernel_end": k1,
                   "nic_supported": n1 is not None, "rcvbuf": rcvbuf, "kernel_error": kc.error}
            ok = len(frames) > 0 and k1 is not None
            record("실제 캡처·커널 통계", "pass" if ok else "fail", det)
        except Exception as e:
            record("실제 캡처·커널 통계", "fail", f"{type(e).__name__}: {e}")
    else:
        record("실제 캡처·커널 통계", "skip", "캡처 장치를 찾지 못함")

    if frames:
        from scapy.layers.l2 import Ether, Loopback
        from netcare.capture.parser import fast_record, parse_packet
        lips = interfaces.local_addresses(iface)[0]
        fast = same = 0
        diffs = []
        for f in frames:
            link = "ether" if f.cls is Ether else "null" if f.cls is Loopback else None
            r1 = fast_record(f.data, f.time, lips, set(), link=link) if link else None
            if r1 is None:
                continue
            fast += 1
            r2 = parse_packet(f.dissect(), lips, set())
            if r1 == r2:
                same += 1
            elif len(diffs) < 3:
                diffs.append(sorted(k for k in set(r1) | set(r2) if r1.get(k) != r2.get(k)))
        record("해석 대조 (빠른 경로 = Scapy)", "pass" if fast and same == fast else ("skip" if not fast else "fail"),
               {"frames": len(frames), "fast_path": fast, "identical": same, "diff_fields": diffs, "link_class": frames[0].cls.__name__})

    # 5. 엔진 실캡처
    if iface:
        try:
            from netcare.capture.engine import Engine
            from netcare.config import ConfigStore
            from netcare.storage.db import Database
            d = Path(tempfile.mkdtemp(prefix="oscheck-"))
            eng = Engine(ConfigStore(d / "config.json"), Database(d / "t.db"), run_probe=False)
            eng.start_live(iface, "")
            time.sleep(min(a.seconds, 60))
            eng._sample_capture()
            last = eng.capture_history[-1] if eng.capture_history else None
            watch = getattr(eng, "_iface_watch", None)
            eng.stop()
            eng.shutdown()
            ok = bool(last) and last.get("app_captured", 0) > 0 and last.get("kernel_recv") is not None
            record("엔진 실캡처·단계별 통계", "pass" if ok else "fail", {"latest": last, "iface_watch": watch})
        except Exception as e:
            record("엔진 실캡처·단계별 통계", "fail", f"{type(e).__name__}: {e}")
    stop.set()

    # 6. 루프백 고속 유입
    lo = None if a.no_loopback else loopback_name()
    if lo:
        try:
            import multiprocessing as mp
            mp.set_start_method("spawn", force=True)
            from scripts.capture_stress import run as stress_run
            rows = []
            for rate in (2000, 10000):
                r = stress_run(rate, 10, lo)
                r.pop("series", None)
                rows.append(r)
            ok = all(r["kernel_recv"] is not None and r["processed"] > 0 for r in rows)
            record("루프백 고속 유입", "pass" if ok else "fail", rows)
        except Exception as e:
            record("루프백 고속 유입", "fail", f"{type(e).__name__}: {e}")
    else:
        record("루프백 고속 유입", "skip", "루프백 캡처 장치 없음 (Windows: Npcap 설치 시 'loopback 지원' 선택 필요)")

    Path(a.out).write_text(json.dumps({"env": env, "results": RESULTS}, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    fails = [r["check"] for r in RESULTS if r["status"] == "fail"]
    print("\n요약:", "모두 통과" if not fails else f"실패 {fails}", "→", a.out)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
