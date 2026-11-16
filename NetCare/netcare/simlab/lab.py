"""Simulation Lab 관리자.

- 실험실 전용 Engine 인스턴스 + 전용 DB(data/simlab.db) → 실제 캡처 데이터(netcare.db)와 저장소 단위로 분리
- 실험실 조치(LabActions)는 가상 효과(Effects)만 바꾼다. remediation.system / firewall 모듈을 import 하지 않으므로
  실제 방화벽·네트워크 설정을 바꾸는 코드 경로가 존재하지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path

from netcare.capture.engine import Engine
from netcare.simlab import evaluate
from netcare.simlab import network as N
from netcare.simlab.scenarios import BENIGN, SCENARIOS, LabGenerator, normalize_params
from netcare.storage import db as dbmod
from netcare.storage.db import Database

log = logging.getLogger("netcare.simlab")

LAB_SCHEMA = """
CREATE TABLE IF NOT EXISTS experiments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL, finished_at REAL,
    benchmark_id INTEGER, scenario TEXT NOT NULL, kind TEXT, title TEXT,
    params TEXT, mode TEXT, response_policy TEXT, session_id INTEGER, base_ts REAL,
    status TEXT NOT NULL, error TEXT,
    packets INTEGER DEFAULT 0, attack_packets INTEGER DEFAULT 0,
    detected INTEGER, latency_sec REAL,
    tp INTEGER, fp INTEGER, fn INTEGER, tn INTEGER,
    precision REAL, recall REAL, f1 REAL, fpr REAL,
    false_alerts TEXT, evidence TEXT, diagnosis TEXT, response TEXT, series TEXT, timeline TEXT,
    pcap_path TEXT, digest TEXT
);
CREATE TABLE IF NOT EXISTS benchmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL, finished_at REAL, config TEXT, status TEXT,
    progress INTEGER DEFAULT 0, total INTEGER DEFAULT 0, summary TEXT
);
"""
dbmod.JSON_FIELDS |= {"false_alerts", "evidence", "diagnosis", "response", "series", "timeline", "config", "summary"}

ATTACKER_OF = {"syn_flood": N.EXT_ATTACKER, "port_scan": N.ATTACKER_IP, "repeated": N.ATTACKER_IP}

LAB_ACTIONS = {
    "host_block": {"title": "내 컴퓨터 방화벽으로 차단 (가상)", "scope": "host",
                   "description": "가상 방화벽이 이 IP에 더 이상 응답하지 않게 해요. 들어오는 패킷은 캡처에 계속 보여요(캡처가 방화벽보다 먼저 일어나는 실제 원리를 따름).",
                   "side_effects": "가상망 안에서만 적용돼요. 실제 방화벽은 바뀌지 않아요."},
    "static_arp": {"title": "공유기 MAC 고정 (가상 정적 ARP)", "scope": "host",
                   "description": "가상 내 컴퓨터가 공유기 MAC을 고정해 위조 ARP 응답을 무시해요.", "side_effects": "가상망 안에서만 적용돼요."},
    "trusted_dns": {"title": "암호화 DNS(DoT)로 전환 (가상)", "scope": "host",
                    "description": "평문 DNS 대신 신뢰할 수 있는 암호화 DNS(10.77.0.54:853)를 써요. 중간에서 응답을 끼워 넣을 수 없어요.",
                    "side_effects": "가상망 안에서만 적용돼요."},
    "ingress_filter": {"title": "공유기 인그레스 필터링 (가상)", "scope": "router",
                       "description": "공유기가 위조 출발지 패킷(내부 대역·예약 주소 사칭)을 들여보내지 않아요.", "side_effects": "가상 공유기 설정이에요. 실제 공유기와 무관해요."},
    "diagnose": {"title": "가상망 연결 진단", "scope": "read",
                 "description": "최근 5초의 실측 지표(RTT, 지터, 손실, DNS·연결 실패)를 정리해요.", "side_effects": "없음"},
    "end_fault": {"title": "장애 주입 종료 (실험 제어)", "scope": "experiment",
                  "description": "장애를 일으키던 조건을 끝내고 회복되는지 관찰해요. NetCare가 장애를 고친 것이 아니라 실험 조건을 바꾼 것이에요.",
                  "side_effects": "실험 제어 장치예요. NetCare의 해결 기능으로 기록하지 않아요."},
}


class LabActions:
    """실험실 전용 조치 관리자: 가상 효과만 변경 (실제 시스템 명령 실행 경로 없음)."""

    def __init__(self, lab: "SimLab"):
        self.lab = lab

    # Engine 이 새 징후마다 호출 → 탐지 기록 + (정책이 auto 면) 권장 가상 조치
    def maybe_auto_block(self, anomaly: dict):
        run = self.lab.current
        if not run:
            return None
        run.on_detect(anomaly)
        if run.policy == "auto" and not run.responded and anomaly["type"] in run.spec.expected:
            remedy = run.spec.remedy
            if remedy == "end_fault":
                self.execute("diagnose", {}, trigger="auto", anomaly_id=anomaly.get("id"))
            if remedy:
                self.execute(remedy, {"ip": ATTACKER_OF.get(run.spec.id)} if remedy == "host_block" else {}, trigger="auto",
                             anomaly_id=anomaly.get("id"))
        return None

    def expire_auto_blocks(self):
        return None

    def catalog(self) -> dict:
        return {"actions": LAB_ACTIONS, "virtual": True}

    def execute(self, action: str, params: dict | None, trigger: str = "user", anomaly_id=None) -> dict:
        run = self.lab.current
        if action not in LAB_ACTIONS:
            raise ValueError(f"알 수 없는 가상 조치예요: {action}")
        if not run:
            raise ValueError("실행 중인 실험이 없어요. 가상 조치는 실험이 진행되는 동안에만 적용돼요.")
        params = dict(params or {})
        e, sec = run.effects, run.cur_sec
        msg = ""
        if action == "host_block":
            ip = params.get("ip") or ATTACKER_OF.get(run.spec.id)
            if not ip:
                raise ValueError("차단할 IP를 지정해 주세요.")
            if ip in (N.GW_IP, N.DNS_IP, N.CLIENT_IP):
                raise ValueError("공유기·DNS 서버·내 컴퓨터 주소는 (가상이라도) 차단하지 않아요.")
            e.host_blocked.add(ip)
            params["ip"] = ip
            msg = f"가상 방화벽: {ip} 에 더 이상 응답하지 않아요."
        elif action == "static_arp":
            e.static_arp = True
            msg = f"가상 정적 ARP: 공유기 {N.GW_IP} = {N.GW_MAC} 로 고정했어요."
        elif action == "trusted_dns":
            e.trusted_dns = True
            msg = "가상 내 컴퓨터가 암호화 DNS(DoT)를 쓰기 시작했어요."
        elif action == "ingress_filter":
            e.ingress_filter = True
            msg = "가상 공유기가 위조 출발지 패킷을 걸러내기 시작했어요."
        elif action == "end_fault":
            e.fault_cleared = True
            msg = "실험 제어: 장애 주입을 종료했어요 (NetCare 의 조치가 아님)."
        elif action == "diagnose":
            msg = run.diagnose()
        if action != "diagnose":
            e.log.append({"sec": sec, "action": action, "params": params, "trigger": trigger})
            if not run.responded:   # 첫 조치 시점부터 효과 적용 → 평가는 그 전까지
                run.responded = True
                run.response_sec = sec + 1   # 다음 초부터 효과 적용
                run.response_action = action
        rec = {"created_at": time.time(), "anomaly_id": anomaly_id, "action": action, "params": params, "trigger": trigger,
               "status": "simulated", "simulated": 1, "result": {"message": msg, "virtual": True, "sec": sec}}
        aid = self.lab.db.insert_action(rec)
        return self.lab.db.get_action(aid)


class _Run:
    def __init__(self, exp_id: int, scenario_id: str, params: dict, policy: str, realtime: bool):
        self.exp_id = exp_id
        self.spec = SCENARIOS[scenario_id]
        self.params = params
        self.policy = policy
        self.realtime = realtime
        self.gen = LabGenerator(scenario_id, params)
        self.effects = N.Effects()
        self.cur_sec = 0
        self.base = float(int(time.time()))
        self.responded = False
        self.response_sec: int | None = None
        self.response_action: str | None = None
        self.detections: list[dict] = []
        self.packets: list = []
        self.digest = hashlib.sha256()
        self.series: list[dict] = []
        self.done = threading.Event()
        self.stopped = False
        self.paused = False

    def on_detect(self, a: dict):
        self.detections.append({"type": a["type"], "severity": a["severity"], "sec": round(a["detected_at"] - self.base, 1),
                                "id": a.get("id")})

    def diagnose(self) -> str:
        lo = max(0, self.cur_sec - 5)
        ms = [self.gen.metrics.get(s) or {} for s in range(lo, self.cur_sec + 1)]
        rtts = [m["rtt"] for m in ms if m.get("rtt") is not None]
        jit = [m["jitter"] for m in ms if m.get("jitter") is not None]
        loss = sum(m.get("loss", 0) for m in ms)
        dnsf = sum(m.get("dnsfail", 0) for m in ms)
        cf = sum(m.get("connfail", 0) for m in ms)
        parts = [f"최근 {len(ms)}초: RTT 중앙값 {sorted(rtts)[len(rtts) // 2]:.0f}ms" if rtts else "RTT 표본 없음",
                 f"지터 {sum(jit) / len(jit):.0f}ms" if jit else "", f"손실 이벤트 {loss}건", f"DNS 실패 {dnsf}건", f"연결 실패 {cf}건"]
        return "가상망 진단 · " + ", ".join(p for p in parts if p)

    def feed(self, put_sync, stop_ev):
        p = self.params
        t_wall0 = time.time()
        for s in range(p["duration"]):
            if stop_ev.is_set():
                self.stopped = True
                break
            self.cur_sec = s
            while self.paused and self.realtime and not stop_ev.is_set():   # 일시정지(실시간 모드): 벽시계 기준점도 함께 미룬다
                time.sleep(0.1)
                t_wall0 += 0.1
            batch = self.gen.step(s, self.effects)
            pkts = []
            for t, pkt, label in batch:
                pkt.time = self.base + t
                pkts.append(pkt)
                self.packets.append(pkt)
                self.digest.update(f"{t:.6f}|{label}|".encode() + bytes(pkt))
            m = self.gen.metrics[s]
            self.series.append({"s": s, "total": m["total"], "attack": m["attack"], "rtt": m.get("rtt"), "jitter": m.get("jitter"),
                                "metric": m.get(self.spec.metric) if self.spec.metric not in ("total",) else m["total"]})
            if self.realtime:
                delay = t_wall0 + s + 1 - time.time()
                if delay > 0 and stop_ev.wait(delay):
                    self.stopped = True
                    break
            if not put_sync(pkts):
                self.stopped = True
                break
        tail = [(t, pkt, lab) for t, pkt, lab in self.gen.drain() if t < p["duration"] + 2]
        for t, pkt, label in tail:
            pkt.time = self.base + t
            self.packets.append(pkt)
            self.digest.update(f"{t:.6f}|{label}|".encode() + bytes(pkt))
        if tail:
            put_sync([x[1] for x in tail])


class SimLab:
    def __init__(self, config, data_dir: Path):
        self.config = config
        self.dir = Path(data_dir)
        (self.dir / "simlab" / "pcap").mkdir(parents=True, exist_ok=True)
        self.db = Database(self.dir / "simlab.db")
        with self.db._wlock:
            self.db._w.executescript(LAB_SCHEMA)
            self.db._w.commit()
        self.actions = LabActions(self)
        self.engine = Engine(config, self.db, action_manager_factory=lambda eng: self.actions, run_probe=False)
        self.current: _Run | None = None
        self._lock = threading.Lock()
        self.bench: dict | None = None
        self._bench_stop = threading.Event()

    # ── 실험 실행 ──
    def scenarios(self) -> list[dict]:
        out = []
        for s in SCENARIOS.values():
            out.append({"id": s.id, "kind": s.kind, "title": s.title, "desc": s.desc, "icon": s.icon, "expected": sorted(s.expected),
                        "acceptable": sorted(s.acceptable), "certainty_note": s.certainty_note, "remedy": s.remedy,
                        "remedy_title": LAB_ACTIONS.get(s.remedy, {}).get("title") if s.remedy else None,
                        "metric_label": s.metric_label, "stage": ["A"], "defaults": normalize_params(s.id, {})})
        return out

    def _insert_exp(self, sid: str, params: dict, policy: str, realtime: bool, benchmark_id=None) -> int:
        spec = SCENARIOS[sid]
        with self.db._wlock:
            cur = self.db._w.execute(
                "INSERT INTO experiments(created_at, benchmark_id, scenario, kind, title, params, mode, response_policy, status) VALUES (?,?,?,?,?,?,?,?,?)",
                (time.time(), benchmark_id, sid, spec.kind, spec.title, json.dumps(params), "realtime" if realtime else "fast", policy, "running"))
            self.db._w.commit()
            return cur.lastrowid

    def _update_exp(self, eid: int, fields: dict):
        sets, vals = [], []
        for k, v in fields.items():
            sets.append(f"{k}=?")
            vals.append(json.dumps(v, ensure_ascii=False) if k in dbmod.JSON_FIELDS else v)
        vals.append(eid)
        with self.db._wlock:
            self.db._w.execute(f"UPDATE experiments SET {', '.join(sets)} WHERE id=?", vals)
            self.db._w.commit()

    def start(self, scenario_id: str, params: dict | None = None, policy: str = "none", realtime: bool = False,
              benchmark_id=None, wait: bool = False) -> int:
        with self._lock:
            if self.current is not None:
                raise RuntimeError("이미 실행 중인 실험이 있어요.")
            p = normalize_params(scenario_id, params)
            policy = policy if policy in ("none", "auto") else "none"
            eid = self._insert_exp(scenario_id, p, policy, realtime, benchmark_id)
            run = _Run(eid, scenario_id, p, policy, realtime)
            self.current = run
        t = threading.Thread(target=self._run, args=(run,), name=f"simlab-exp-{eid}", daemon=True)
        t.start()
        if wait:
            run.done.wait()
        return eid

    def _run(self, run: _Run):
        try:
            sess = self.engine.run_generated(f"[시뮬레이션] {run.spec.title}", {N.CLIENT_IP}, {N.CLIENT_MAC}, N.GW_IP, run.feed)
            self._update_exp(run.exp_id, {"session_id": sess["id"], "base_ts": run.base})
            # 처리 완료 대기
            while not (self.engine.session and self.engine.session.get("finished")) and self.engine.state == "simulating":
                time.sleep(0.05)
            time.sleep(0.4)   # 마지막 DB 저장 대기
            self._finalize(run, sess["id"])
        except Exception as e:
            log.exception("experiment failed")
            self._update_exp(run.exp_id, {"status": "failed", "error": str(e)[:300], "finished_at": time.time()})
        finally:
            self.current = None
            run.done.set()

    def _finalize(self, run: _Run, sid: int):
        anomalies = self.db.query("SELECT * FROM anomalies WHERE session_id=? ORDER BY detected_at", (sid,))
        W = self.config.cfg.detection.window_sec
        sc = evaluate.score(run.spec, run.params, anomalies, run.base, W, stop_sec=run.response_sec)
        first = next((a for a in anomalies if a["type"] in run.spec.expected), None)
        evidence = diagnosis = None
        if first:
            evidence = {"type": first["type"], "severity": first["severity"], "criterion": first["criterion"],
                        "threshold": first["threshold"], "measured": first["measured"], "peak": first["peak"], "evidence": first["evidence"]}
            ex = first.get("explanation") or {}
            diagnosis = {"title": ex.get("title"), "summary": ex.get("summary"), "certainty": ex.get("certainty_label"),
                         "analysis": ex.get("analysis"), "recommendations": [r.get("title") for r in ex.get("recommendations", [])]}
        response = None
        if run.effects.log:
            act = run.effects.log[0]
            ba = evaluate.before_after(run.gen.metrics, run.spec.metric, act["sec"] + 1, run.params["attack_end"], run.spec.metric_better,
                                       run.params["attack_start"])
            later = [a for a in anomalies if a["type"] in run.spec.expected and a["last_seen"] - run.base > act["sec"] + 1]
            response = {"actions": run.effects.log, "first_action": act["action"], "first_action_title": LAB_ACTIONS[act["action"]]["title"],
                        "at_sec": act["sec"] + 1, "metric_label": run.spec.metric_label, "comparison": ba,
                        "success": bool(ba and ba.get("improved")), "anomaly_continued_after": bool(later),
                        "experiment_control": act["action"] == "end_fault",
                        "note": ("장애 주입 종료는 실험 제어이며 NetCare의 해결 기능이 아니에요." if act["action"] == "end_fault" else
                                 "가상 효과 모델에서 조치가 성공했을 때의 결과예요. 실제 효과를 증명하지는 않아요.")}
        pcap = self.dir / "simlab" / "pcap" / f"exp_{run.exp_id}.pcap"
        try:
            from scapy.utils import wrpcap
            wrpcap(str(pcap), run.packets)
        except Exception:
            pcap = None
        types_at = {r["s"]: r["active"] for r in sc["timeline"]}
        series = [{**x, "detected": types_at.get(x["s"], [])} for x in run.series]
        self._update_exp(run.exp_id, {
            "status": "stopped" if run.stopped else "completed", "finished_at": time.time(),
            "packets": run.gen.packets_total, "attack_packets": run.gen.packets_attack,
            "detected": None if sc["detected"] is None else int(sc["detected"]), "latency_sec": sc["latency_sec"],
            "tp": sc["tp"], "fp": sc["fp"], "fn": sc["fn"], "tn": sc["tn"], "precision": sc["precision"], "recall": sc["recall"],
            "f1": sc["f1"], "fpr": sc["fpr"], "false_alerts": sc["false_alerts"], "evidence": evidence, "diagnosis": diagnosis,
            "response": response, "series": series, "timeline": sc["timeline"], "pcap_path": str(pcap) if pcap else None,
            "digest": run.digest.hexdigest()})

    def stop(self):
        self._bench_stop.set()
        if self.current:
            self.current.paused = False
            self.engine.stop()

    def pause(self, paused: bool | None = None) -> bool:
        """실시간 실험 일시정지/재개. paused 가 None 이면 토글."""
        run = self.current
        if not run or not run.realtime:
            return False
        run.paused = (not run.paused) if paused is None else bool(paused)
        return run.paused

    # ── 조회 ──
    def status(self) -> dict:
        run = self.current
        st = {"running": bool(run), "benchmark": self.bench}
        if run:
            st["experiment"] = {"id": run.exp_id, "scenario": run.spec.id, "title": run.spec.title, "kind": run.spec.kind,
                                "sec": run.cur_sec, "duration": run.params["duration"], "attack_start": run.params["attack_start"],
                                "attack_end": run.params["attack_end"], "policy": run.policy, "mode": "realtime" if run.realtime else "fast", "paused": run.paused,
                                "series": run.series[-180:], "detections": run.detections[-50:], "effects_log": run.effects.log,
                                "metric_label": run.spec.metric_label, "remedy": run.spec.remedy,
                                "remedy_title": LAB_ACTIONS.get(run.spec.remedy, {}).get("title") if run.spec.remedy else None}
        return st

    def experiments(self, limit: int = 200, benchmark_id: int | None = None) -> list[dict]:
        cols = "id, created_at, finished_at, benchmark_id, scenario, kind, title, params, mode, response_policy, status, packets, attack_packets, detected, latency_sec, tp, fp, fn, tn, precision, recall, f1, fpr, false_alerts"
        if benchmark_id is not None:
            return self.db.query(f"SELECT {cols} FROM experiments WHERE benchmark_id=? ORDER BY id", (benchmark_id,))
        return self.db.query(f"SELECT {cols} FROM experiments ORDER BY id DESC LIMIT ?", (limit,))

    def experiment(self, eid: int) -> dict | None:
        e = self.db.query_one("SELECT * FROM experiments WHERE id=?", (eid,))
        if not e:
            return None
        if e.get("session_id"):
            e["anomalies"] = self.db.query("SELECT id, type, severity, detected_at, last_seen, criterion, threshold, measured, peak, count, evidence, explanation FROM anomalies WHERE session_id=? ORDER BY detected_at", (e["session_id"],))
            e["actions"] = self.db.query("SELECT * FROM actions WHERE created_at >= ? AND created_at <= ? ORDER BY id",
                                         (e["created_at"] - 1, (e["finished_at"] or time.time()) + 1))
        return e

    # ── 벤치마크 (반복 실행 + 강도 단계) ──
    def start_benchmark(self, scenarios: list[str] | None, intensities: list[float] | None, seeds: list[int] | None) -> int:
        if self.current is not None or (self.bench and self.bench.get("status") == "running"):
            raise RuntimeError("이미 실행 중인 실험이 있어요.")
        scenarios = [s for s in (scenarios or list(SCENARIOS)) if s in SCENARIOS]
        intensities = [float(x) for x in (intensities or [1.0])][:6]
        seeds = [int(x) for x in (seeds or [1, 2, 3])][:10]
        jobs = [(s, i, seed) for s in scenarios for i in intensities for seed in seeds]
        cfg = {"scenarios": scenarios, "intensities": intensities, "seeds": seeds}
        with self.db._wlock:
            cur = self.db._w.execute("INSERT INTO benchmarks(created_at, config, status, total) VALUES (?,?,?,?)",
                                     (time.time(), json.dumps(cfg), "running", len(jobs)))
            self.db._w.commit()
            bid = cur.lastrowid
        self.bench = {"id": bid, "status": "running", "progress": 0, "total": len(jobs), "config": cfg}
        self._bench_stop.clear()

        def worker():
            done = 0
            for sid, inten, seed in jobs:
                if self._bench_stop.is_set():
                    break
                try:
                    self.start(sid, {"intensity": inten, "seed": seed}, "none", False, benchmark_id=bid, wait=True)
                except Exception:
                    log.exception("benchmark job failed")
                done += 1
                self.bench["progress"] = done
                with self.db._wlock:
                    self.db._w.execute("UPDATE benchmarks SET progress=? WHERE id=?", (done, bid))
                    self.db._w.commit()
            summary = self.benchmark_summary(bid)
            status = "stopped" if self._bench_stop.is_set() else "completed"
            with self.db._wlock:
                self.db._w.execute("UPDATE benchmarks SET status=?, finished_at=?, summary=? WHERE id=?",
                                   (status, time.time(), json.dumps(summary, ensure_ascii=False), bid))
                self.db._w.commit()
            self.bench = {**self.bench, "status": status}
        threading.Thread(target=worker, name="simlab-benchmark", daemon=True).start()
        return bid

    def benchmark_summary(self, bid: int) -> dict:
        exps = [e for e in self.experiments(benchmark_id=bid) if e["status"] == "completed"]
        agg = evaluate.aggregate(exps)
        curve = {}
        for e in exps:
            if e["kind"] == "baseline":
                continue
            inten = (e.get("params") or {}).get("intensity")
            c = curve.setdefault(e["scenario"], {})
            k = str(inten)
            d = c.setdefault(k, [0, 0])
            d[0] += 1
            d[1] += 1 if e.get("detected") else 0
        agg["intensity_curve"] = {s: {k: round(v[1] / v[0], 3) for k, v in sorted(c.items(), key=lambda kv: float(kv[0]))}
                                  for s, c in curve.items()}
        return agg

    def benchmarks(self) -> list[dict]:
        return self.db.query("SELECT * FROM benchmarks ORDER BY id DESC LIMIT 50")

    def shutdown(self):
        self.stop()
        self.engine.shutdown()
