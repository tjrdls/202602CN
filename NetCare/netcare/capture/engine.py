"""캡처 엔진: 캡처 스레드 → 제한 큐 → 처리 스레드 → 통계/탐지/저장.

스레드 구성
- sniffer  : Scapy AsyncSniffer. 콜백은 큐에 넣기만 한다 (가득 차면 버리고 dropped 증가).
- processor: 큐에서 배치로 꺼내 파싱 → LiveStats → Detector → SQLite.
- ticker   : 1초마다 탐지 평가, 이상 징후 상태 갱신, 스니퍼 오류 감시.
- prober   : 설정 간격마다 ping/DNS 실측 → 건강 점수 기록, 자동 차단 만료 처리.
- feeder   : (pcap 가져오기 / 테스트 시나리오일 때만) 패킷을 큐에 공급.

한 번에 하나의 세션(live | pcap | test)만 활성화된다.
"""
from __future__ import annotations

import logging
import platform
import queue
import threading
import time
from pathlib import Path

from netcare.analysis import health, probe
from netcare.analysis.stats import LiveStats
from netcare.capture import interfaces
from netcare.capture.parser import parse_packet
from netcare.config import ConfigStore
from netcare.detection.detector import SEVERITY_ORDER, Detector, probe_anomalies
from netcare.diagnosis.explainer import explain
from netcare.storage.db import Database

log = logging.getLogger("netcare.engine")

PERMISSION_HELP = {
    "Darwin": "macOS: 터미널에서 'sudo .venv/bin/python run.py' 로 실행하거나, Wireshark 의 ChmodBPF 를 설치해 /dev/bpf* 접근 권한(access_bpf 그룹)을 받으세요.",
    "Linux": "Linux: 'sudo .venv/bin/python run.py' 로 실행하거나 'sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)' 로 캡처 권한을 주세요.",
    "Windows": "Windows: Npcap(https://npcap.com)을 설치하고, 명령 프롬프트를 '관리자 권한으로 실행'한 뒤 다시 시작하세요.",
}


class CaptureError(Exception):
    def __init__(self, message: str, code: str = "capture_error", help: str = ""):
        super().__init__(message)
        self.code, self.help = code, help


class Engine:
    def __init__(self, config: ConfigStore, db: Database, action_manager_factory=None, run_probe: bool = True):
        self.run_probe_enabled = run_probe
        self.config = config
        self.db = db
        self.stats = LiveStats()
        self.detector = Detector(config.cfg.detection)
        self.queue: queue.Queue = queue.Queue(maxsize=config.cfg.queue_size)
        self._lock = threading.RLock()
        self._eval_lock = threading.RLock()
        self._stop = threading.Event()
        self.sniffer = None
        self.feeder: threading.Thread | None = None
        self._feed_stop = threading.Event()
        self.session: dict | None = None      # {id, source, iface, bpf, started, title}
        self.state = "idle"                    # idle | capturing | importing | testing | error
        self.error: dict | None = None
        self.dropped = 0
        self.processed = 0
        self.local_ips, self.local_macs = interfaces.local_addresses()
        self.gateway = interfaces.default_route()[1]
        self.dns_servers = interfaces.dns_servers()
        self.names: dict[str, str] = db.load_names()
        self._pending_names: dict[str, str] = {}
        self.active: dict[tuple, dict] = {}    # 진행 중 징후 key → {id, last_seen, ...}
        self.probe_result: dict | None = None
        self.health: dict = health.compute([], None)
        self.offline_clock: float | None = None  # pcap 분석 시 '현재 시각' 역할
        self._eval_sec: int | None = None
        self._last_packet_wall = 0.0
        self.actions = action_manager_factory(self) if action_manager_factory else None
        self._threads = [threading.Thread(target=self._process_loop, name="netcare-processor", daemon=True),
                         threading.Thread(target=self._tick_loop, name="netcare-ticker", daemon=True),
                         threading.Thread(target=self._probe_loop, name="netcare-prober", daemon=True)]
        for t in self._threads:
            t.start()

    # ───────────── 컨텍스트 (진단/조치에서 사용) ─────────────
    def context(self) -> dict:
        test = self.session and self.session["source"] == "test"
        from netcare.testdata import synthetic
        if self.session and self.session["source"] == "sim":
            lips = set(self._session_local[0])
        else:
            lips = ({synthetic.LOCAL_IP} | self.local_ips) if test else self.local_ips
        return {"local_ips": lips,
                "gateway": self.gateway, "dns_servers": self.dns_servers, "names": self.names,
                "capturing": self.state == "capturing", "z": self.config.cfg.detection.traffic_z_threshold}

    def _packet_clock(self) -> bool:
        """pcap 분석·가상 실험은 '패킷 시각'을 현재 시각으로 쓴다."""
        return bool(self.session and self.session["source"] in ("pcap", "sim"))

    def now(self) -> float:
        return self.offline_clock if (self._packet_clock() and self.offline_clock) else time.time()

    # ───────────── 세션 관리 ─────────────
    def _begin(self, source: str, iface: str | None, bpf: str | None, title: str, local_ips=None, local_macs=None) -> dict:
        self.stop()
        with self._lock:
            # 큐 비우기
            while not self.queue.empty():
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    break
            self.stats.reset()
            self.detector = Detector(self.config.cfg.detection)
            self.active.clear()
            self.dropped = self.processed = 0
            self.offline_clock = None
            self._eval_sec = None
            self._last_packet_wall = 0.0
            self.error = None
            if local_ips is None:
                self.local_ips, self.local_macs = interfaces.local_addresses(iface)
                self.gateway = interfaces.default_route()[1]
                self.dns_servers = interfaces.dns_servers()
                self._session_local = (self.local_ips, self.local_macs)
            else:
                self._session_local = (local_ips, local_macs or set())
            self.detector.local_ips = self._session_local[0]
            self.detector.local_macs = self._session_local[1]
            self.detector.gateway_ip = getattr(self, "_session_gateway", None) or self.gateway
            import ipaddress as _ip
            nets = getattr(self, "_session_nets", None)
            if nets is None:
                nets = interfaces.local_networks(iface) if source == "live" else []
            self.detector.local_nets = [_ip.ip_network(n, strict=False) for n in nets]
            sid = self.db.create_session(source, iface, bpf, title)
            self.session = {"id": sid, "source": source, "iface": iface, "bpf": bpf or "", "started": time.time(),
                            "title": title, "ended": None, "finished": False}
            return self.session

    def start_live(self, iface: str, bpf: str = "") -> dict:
        from scapy.all import AsyncSniffer
        from scapy.arch.common import compile_filter
        if not iface:
            raise CaptureError("캡처할 네트워크 인터페이스를 선택해 주세요.", "no_iface")
        cap_iface = interfaces.resolve_capture_iface(iface)
        if cap_iface is None:
            raise CaptureError(f"'{iface}' 인터페이스를 찾을 수 없어요.", "no_iface",
                               PERMISSION_HELP.get("Windows", "") if platform.system() == "Windows" else "")
        bpf = (bpf or "").strip()
        if bpf:
            try:
                compile_filter(bpf, iface=cap_iface)
            except Exception as e:
                raise CaptureError(f"캡처 필터 문법이 올바르지 않아요: {bpf}", "bad_filter",
                                   "예시: 'tcp port 443', 'udp', 'host 192.168.0.1', 'not port 22'. 자세한 오류: " + str(e)[:200])
        sess = self._begin("live", iface, bpf, f"{iface} 실시간 캡처")
        try:
            def _open(promisc: bool):
                x = AsyncSniffer(iface=cap_iface, filter=bpf or None, prn=self._enqueue_live, store=False, promisc=promisc)
                x.start()
                time.sleep(0.3)
                if x.exception is not None:
                    raise x.exception
                if not x.running:
                    raise CaptureError("캡처를 시작하지 못했어요.")
                return x
            try:
                sn = _open(True)
            except Exception as e1:
                # Wi-Fi 등 일부 인터페이스는 무차별(promiscuous) 모드를 허용하지 않는다 → 내 컴퓨터 통신만 보는 모드로 다시 시도
                if "promisc" not in str(e1).lower():
                    raise
                sn = _open(False)
                sess["promisc"] = False
                log.info("promiscuous mode unavailable on %s; capturing own traffic only", iface)
        except Exception as e:
            self._end_session()
            self.state = "error"
            msg = str(e)
            if isinstance(e, PermissionError) or "ermission" in msg or "Operation not permitted" in msg:
                self.error = {"message": "패킷을 캡처할 권한이 없어요.", "help": PERMISSION_HELP.get(platform.system(), ""), "code": "permission"}
                raise CaptureError(self.error["message"], "permission", self.error["help"])
            self.error = {"message": f"캡처 시작 실패: {msg[:300]}", "help": "", "code": "capture_error"}
            raise CaptureError(self.error["message"])
        with self._lock:
            self.sniffer = sn
            self.state = "capturing"
            self.config.update({"interface": iface, "bpf_filter": bpf})
        log.info("live capture started on %s filter=%r", iface, bpf)
        return sess

    def _enqueue_live(self, pkt):
        try:
            self.queue.put_nowait((pkt, "live"))
        except queue.Full:
            self.dropped += 1

    def import_pcap(self, path: str | Path, display_name: str) -> dict:
        from scapy.utils import PcapReader
        try:
            reader = PcapReader(str(path))
        except Exception as e:
            raise CaptureError(f"pcap 파일을 읽을 수 없어요: {e}", "bad_pcap")
        sess = self._begin("pcap", None, None, f"파일 분석: {display_name}")
        self.state = "importing"
        self._feed_stop.clear()

        def feed():
            n = 0
            try:
                for pkt in reader:
                    if self._feed_stop.is_set():
                        break
                    self.queue.put((pkt, "pcap"))  # 파일은 버리지 않고 기다렸다가 넣음
                    n += 1
            except Exception as e:
                self.error = {"message": f"pcap 읽기 중 오류: {e}", "help": "", "code": "bad_pcap"}
            finally:
                reader.close()
                self.queue.put((None, ("eof", sess["id"])))
        self.feeder = threading.Thread(target=feed, name="netcare-pcap", daemon=True)
        self.feeder.start()
        return sess

    def run_test(self, scenario: str) -> dict:
        from netcare.testdata import synthetic
        if scenario not in synthetic.SCENARIOS:
            raise CaptureError(f"알 수 없는 테스트 시나리오예요: {scenario}", "bad_scenario")
        info = synthetic.SCENARIOS[scenario]
        sess = self._begin("test", "테스트", None, f"[테스트 데이터] {info['title']}",
                           local_ips={synthetic.LOCAL_IP}, local_macs={synthetic.LOCAL_MAC})
        sess["scenario"] = scenario
        self.state = "testing"
        self._feed_stop.clear()

        def feed():
            t0 = time.time()
            for sec, pkts in synthetic.generate(scenario):
                if self._feed_stop.is_set():
                    break
                # 실시간처럼 보이도록 초 단위로 내보내며, 타임스탬프를 현재 시각으로 찍는다
                target = t0 + sec
                delay = target - time.time()
                if delay > 0 and self._feed_stop.wait(delay):
                    break
                base = time.time()
                for i, p in enumerate(pkts):
                    p.time = base + (i / max(len(pkts), 1)) * 0.95
                    self.queue.put((p, "test"))
            self.queue.put((None, ("eof", sess["id"])))
        self.feeder = threading.Thread(target=feed, name="netcare-test", daemon=True)
        self.feeder.start()
        return sess

    def run_generated(self, title: str, local_ips: set, local_macs: set, gateway: str | None, feed, source: str = "sim") -> dict:
        """가상 실험실: feed(put_sync, stop_event) 가 만든 패킷을 같은 파이프라인으로 처리한다.

        put_sync(packets) 는 패킷을 큐에 넣고 '모두 처리될 때까지' 기다린다. 그래서 탐지 → 가상 조치 → 다음 초 생성의
        인과 관계가 매번 같은 순서로 일어나 실험이 재현된다. 이 경로는 실제 네트워크 인터페이스를 열지 않는다.
        """
        self._session_gateway = gateway
        self._session_nets = ["10.77.0.0/24"]
        sess = self._begin(source, "가상 실험실", None, title, local_ips=set(local_ips), local_macs=set(local_macs))
        self.detector.gateway_ip = gateway
        self.state = "simulating"
        self._feed_stop.clear()
        self._fed = 0

        def put_sync(pkts) -> bool:
            for p in pkts:
                self.queue.put((p, source))
                self._fed += 1
            while self.processed < self._fed and not self._feed_stop.is_set():
                time.sleep(0.001)
            return not self._feed_stop.is_set()

        def run():
            try:
                feed(put_sync, self._feed_stop)
            except Exception:
                log.exception("simulation feed failed")
                self.error = {"message": "가상 실험 생성 중 오류가 발생했어요.", "help": "", "code": "sim_error"}
            finally:
                self.queue.put((None, ("eof", sess["id"])))
        self.feeder = threading.Thread(target=run, name="netcare-simlab", daemon=True)
        self.feeder.start()
        return sess

    def stop(self) -> dict | None:
        with self._lock:
            sn, self.sniffer = self.sniffer, None
            self._feed_stop.set()
        if sn is not None:
            try:
                sn.stop(join=True)
            except Exception:
                pass
        if self.feeder and self.feeder.is_alive():
            self.feeder.join(timeout=3)
        # 남은 큐 처리 대기 (최대 3초)
        t0 = time.time()
        while not self.queue.empty() and time.time() - t0 < 3:
            time.sleep(0.05)
        return self._end_session()

    def _end_session(self) -> dict | None:
        with self._lock:
            s = self.session
            if s and not s.get("ended"):
                s["ended"] = time.time()
                self.db.end_session(s["id"], self.processed, self.dropped)
            if self.state in ("capturing", "importing", "testing", "simulating"):
                self.state = "idle"
            return s

    # ───────────── 처리 루프 ─────────────
    def _process_loop(self):
        batch, last_flush = [], time.time()
        while not self._stop.is_set():
            try:
                item = self.queue.get(timeout=0.2)
            except queue.Empty:
                item = None
            if item is not None:
                pkt, source = item
                if pkt is None:
                    self._flush(batch)
                    batch = []
                    if self.session and source[1] == self.session["id"]:
                        self._finish_feed()
                    continue
                try:
                    batch.append(self._handle_packet(pkt, source))
                except Exception:
                    log.exception("packet handling failed")
            if batch and (len(batch) >= 500 or time.time() - last_flush > 0.3):
                self._flush(batch)
                batch, last_flush = [], time.time()
            elif not batch:
                last_flush = time.time()

    def _handle_packet(self, pkt, source: str) -> dict:
        cfg = self.config.cfg
        lips, lmacs = getattr(self, "_session_local", (self.local_ips, self.local_macs))
        rec = parse_packet(pkt, lips, lmacs, source=source, snaplen=cfg.raw_snaplen, store_raw=cfg.store_raw)
        if not rec["ts"]:
            rec["ts"] = time.time()
        if source in ("pcap", "sim"):
            self.offline_clock = rec["ts"]
        # 탐지 평가는 '처리한 패킷의 시각'을 기준으로 1초마다 한다.
        # (패킷이 몰려 처리가 실제 시각보다 늦어져도, 평가 창이 아직 처리 안 된 빈 구간을 보지 않도록)
        sec = int(rec["ts"])
        if self._eval_sec is None:
            self._eval_sec = sec
        elif sec > self._eval_sec:
            self._eval_sec = sec
            self._evaluate(sec)
        self._last_packet_wall = time.time()
        self.stats.add(rec)
        self.detector.observe(rec)
        if rec.get("dns_answers") and rec.get("dns_qname"):
            for ip in rec["dns_answers"]:
                if self.names.get(ip) != rec["dns_qname"]:
                    if len(self.names) >= 20000:   # 장시간 실행 시 무한히 자라지 않도록 오래된 항목부터 버림
                        for old_ip in list(self.names)[:2000]:
                            self.names.pop(old_ip, None)
                    self.names[ip] = rec["dns_qname"]
                    self._pending_names[ip] = rec["dns_qname"]
        self.processed += 1
        return rec

    def _flush(self, batch: list[dict]):
        if not batch or not self.session:
            return
        try:
            self.db.insert_packets(self.session["id"], batch, self.config.cfg.max_db_packets)
            self.db.add_traffic(self.session["id"], self.session["source"], self.stats.pop_minutes())
            if self._pending_names:
                names, self._pending_names = self._pending_names, {}
                self.db.upsert_names(names)
        except Exception:
            log.exception("DB write failed")

    def _finish_feed(self):
        if self.session and self.session["source"] in ("pcap", "sim") and self.offline_clock:
            self._evaluate(self.offline_clock + 1)
        if self.session:
            self.session["finished"] = True
        self._end_session()

    # ───────────── 탐지 / 이상 징후 관리 ─────────────
    def _evaluate(self, now: float):
        if not self.session:
            return
        with self._eval_lock:  # 처리 스레드와 ticker 가 동시에 평가하지 않도록
            try:
                cands = self.detector.evaluate(now)
            except Exception:
                log.exception("detector failed")
                return
            self.handle_candidates(cands, now)

    def handle_candidates(self, cands: list[dict], now: float, probe: bool = False):
        if probe:
            # 연결 품질 징후는 실제 시스템 측정이므로 항상 실데이터(live), 세션과 무관
            src_label, sid = "live", None
        elif not self.session:
            src_label, sid = "live", None
        else:
            src_label, sid = self.session["source"], self.session["id"]
        cooldown = self.config.cfg.detection.cooldown_sec
        ctx = self.context()
        for c in cands:
            key = (c["type"], c.get("src"), c.get("dst"), c.get("port"))
            cur = self.active.get(key)
            if cur and now - cur["last_seen"] <= cooldown:
                peak = max(cur["peak"], c["measured"] or 0)
                sev = c["severity"] if SEVERITY_ORDER[c["severity"]] > SEVERITY_ORDER[cur["severity"]] else cur["severity"]
                cur.update(last_seen=now, peak=peak, severity=sev, count=cur["count"] + 1)
                upd = {"last_seen": now, "measured": c["measured"], "peak": peak, "count": cur["count"],
                       "severity": sev, "evidence": c.get("evidence"), "status": "active"}
                if sev != cur.get("explained_sev"):
                    full = {**c, "severity": sev, "source": src_label}
                    upd["explanation"] = explain(full, ctx)
                    cur["explained_sev"] = sev
                self.db.update_row("anomalies", cur["id"], upd)
                continue
            a = {**c, "session_id": sid, "source": src_label, "detected_at": now, "last_seen": now,
                 "peak": c["measured"], "count": 1, "status": "active"}
            a["explanation"] = explain(a, ctx)
            aid = self.db.insert_anomaly(a)
            a["id"] = aid
            self.active[key] = {"id": aid, "last_seen": now, "peak": c["measured"] or 0, "severity": c["severity"],
                                "count": 1, "explained_sev": c["severity"]}
            log.info("anomaly #%s %s %s src=%s", aid, c["type"], c["severity"], c.get("src"))
            if self.actions:
                try:
                    self.actions.maybe_auto_block(a)
                except Exception:
                    log.exception("auto block failed")

    def _expire_active(self, now: float):
        cooldown = self.config.cfg.detection.cooldown_sec
        for key, cur in list(self.active.items()):
            if now - cur["last_seen"] > cooldown:
                row = self.db.get_anomaly(cur["id"])
                if row and row["status"] == "active":
                    self.db.update_row("anomalies", cur["id"], {"status": "ended"})
                del self.active[key]

    def _tick_loop(self):
        while not self._stop.wait(1.0):
            try:
                sn = self.sniffer
                if sn is not None and self.state == "capturing" and not sn.running:
                    err = sn.exception
                    self.state = "error"
                    self.error = {"message": f"캡처가 예기치 않게 멈췄어요: {err or '인터페이스 연결이 끊겼을 수 있어요'}",
                                  "help": "인터페이스 상태를 확인하고 다시 시작해 주세요.", "code": "sniffer_died"}
                    self.sniffer = None
                    self._end_session()
                if self.state in ("capturing", "testing"):
                    # 패킷이 한동안 없을 때만 실제 시각으로 평가 (창이 비워지며 징후가 자연스럽게 끝나도록)
                    if time.time() - self._last_packet_wall > 2 and self.queue.empty():
                        self._evaluate(time.time())
                    self.stats.prune(time.time())
                if self._packet_clock():
                    if self.offline_clock:
                        self._expire_active(self.offline_clock)
                else:
                    self._expire_active(time.time())
                self.health = self._compute_health()
            except Exception:
                log.exception("ticker failed")

    def _compute_health(self) -> dict:
        now = self.now()
        rows = self.db.list_anomalies(status="active", limit=200)
        real = not self.session or self.session["source"] == "live"
        if self.session:
            # 현재 세션의 징후 + (실시간 캡처일 때만) 세션과 무관한 연결 품질 징후
            rows = [r for r in rows if r.get("session_id") == self.session["id"] or (real and r.get("session_id") is None)]
        probe_for_health = self.probe_result if real else None
        note = None if real else {"test": "테스트 데이터 세션에서는 실제 연결 측정을 점수에 넣지 않아요",
                                  "sim": "가상 실험실에서는 실제 연결 측정을 점수에 넣지 않아요"}.get(
                                      self.session["source"], "파일 분석 중에는 현재 연결 측정을 점수에 넣지 않아요")
        return health.compute(rows, probe_for_health, now, probe_note=note)

    def _probe_loop(self):
        last_health_store = 0.0
        time.sleep(2)
        while not self._stop.is_set():
            pc = self.config.cfg.probe
            try:
                if pc.enabled and self.run_probe_enabled:
                    self.run_probe_now()
                if self.actions:
                    self.actions.expire_auto_blocks()
                if time.time() - last_health_store >= 30:
                    h = self.health
                    s = self.session
                    self.db.insert_health(s["id"] if s else None, s["source"] if s else "live", h["score"], h["status"], h["components"])
                    last_health_store = time.time()
            except Exception:
                log.exception("probe loop failed")
            self._stop.wait(max(5, pc.interval_sec))

    def run_probe_now(self) -> dict:
        pc = self.config.cfg.probe
        self.gateway = interfaces.default_route()[1] or self.gateway
        r = probe.run_probe(self.gateway, pc.external_target, pc.dns_test_domains)
        self.probe_result = r
        cands = probe_anomalies(r, pc)
        if cands:
            with self._eval_lock:
                self.handle_candidates(cands, time.time(), probe=True)
        self.health = self._compute_health()
        return r

    # ───────────── 상태 조회 ─────────────
    def status(self) -> dict:
        s = self.session
        return {
            "state": self.state, "session": s, "error": self.error,
            "dropped": self.dropped, "processed": self.processed, "queue": self.queue.qsize(),
            "queue_max": self.queue.maxsize,
            "local_ips": sorted(self.local_ips)[:20], "gateway": self.gateway, "dns_servers": self.dns_servers,
            "baseline": self.detector.baseline_info(),
        }

    def snapshot(self) -> dict:
        now = self.now()
        if self.session and self.session["source"] == "pcap":
            now = (self.stats.last_ts or now) + 1
        return self.stats.snapshot(now)

    def shutdown(self):
        """프로그램 종료: 캡처·피드 중지 → 처리 스레드 종료 대기 → DB 연결 정리."""
        self.stop()
        self._stop.set()
        for t in getattr(self, "_threads", []):
            if t.is_alive() and t is not threading.current_thread():
                t.join(timeout=3)
        try:
            self.db.close()
        except Exception:
            pass
