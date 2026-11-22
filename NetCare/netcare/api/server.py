"""FastAPI 웹 서버: REST API + 정적 웹 UI.

보안
- 127.0.0.1 에만 바인딩 (run.py)
- Host 헤더 검사: DNS 리바인딩 공격 방지
- 상태를 바꾸는 요청(POST/PUT/DELETE)은 'X-NetCare: 1' 헤더 필수
  → 다른 웹사이트가 몰래 요청을 보내면 브라우저가 CORS preflight 로 막는다 (CORS 허용 안 함)
"""
from __future__ import annotations

import logging
import mimetypes
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Body, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from netcare import __version__
from netcare.analysis import terms
from netcare.capture import interfaces
from netcare.capture.engine import CaptureError, Engine
from netcare.capture.parser import dissect
from netcare.config import DATA_DIR, ConfigStore
from netcare.detection.rules import rule_catalog
from netcare.diagnosis.explainer import TYPE_LABELS, explain
from netcare.remediation import system
from netcare.remediation.actions import CATALOG, ActionError, ActionManager
from netcare.reporting import export
from netcare.storage.db import Database
from netcare.testdata import synthetic

log = logging.getLogger("netcare.api")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


def _plotly_js() -> Path | None:
    try:
        import plotly
        p = Path(plotly.__file__).parent / "package_data" / "plotly.min.js"
        return p if p.exists() else None
    except ImportError:
        return None


def create_app(data_dir: Path | None = None, start_probe: bool = True) -> FastAPI:
    data_dir = Path(data_dir or DATA_DIR)
    config = ConfigStore(data_dir / "config.json")
    db = Database(data_dir / "netcare.db")
    engine = Engine(config, db, action_manager_factory=lambda eng: ActionManager(db, eng.context, lambda: config.cfg),
                    run_probe=start_probe)
    from netcare.simlab.lab import SimLab
    lab = SimLab(config, data_dir)      # 별도 Engine + 별도 DB(simlab.db): 실제 캡처 데이터와 저장소 단위로 분리
    app = FastAPI(title="NetCare", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.state.engine, app.state.db, app.state.config, app.state.lab = engine, db, config, lab

    @app.middleware("http")
    async def security(request: Request, call_next):
        host = request.url.hostname or ""
        if host not in ALLOWED_HOSTS:
            return JSONResponse({"detail": "허용되지 않은 호스트예요."}, status_code=403)
        if request.method in ("POST", "PUT", "DELETE", "PATCH") and request.headers.get("x-netcare") != "1":
            return JSONResponse({"detail": "요청 확인 헤더가 없어요."}, status_code=403)
        return await call_next(request)

    @app.exception_handler(CaptureError)
    async def capture_err(_req, e: CaptureError):
        return JSONResponse({"detail": str(e), "code": e.code, "help": e.help}, status_code=400)

    @app.exception_handler(ActionError)
    async def action_err(_req, e: ActionError):
        return JSONResponse({"detail": str(e), "code": e.code, **e.extra}, status_code=400)

    @app.on_event("shutdown")
    def _shutdown():
        engine.shutdown()
        lab.shutdown()

    # ───────── 정적 파일 ─────────
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/vendor/plotly.min.js", include_in_schema=False)
    def plotly_js():
        p = _plotly_js()
        if not p:
            raise HTTPException(404, "plotly 패키지가 설치되어 있지 않아요 (pip install plotly)")
        return FileResponse(p, media_type="application/javascript", headers={"Cache-Control": "max-age=86400"})

    # Windows 레지스트리가 .js 를 text/plain 으로 알려주면 ES 모듈 로드가 거부되므로 명시한다
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("text/css", ".css")
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    # ───────── 상태 / 인터페이스 / 캡처 ─────────
    def full_status() -> dict:
        st = engine.status()
        st.update(version=__version__, is_admin=system.is_admin(), platform=system.SYSTEM, can_elevate=system.can_elevate(),
                  config={"interface": config.cfg.interface, "bpf_filter": config.cfg.bpf_filter,
                          "auto_block_enabled": config.cfg.auto_block_enabled, "expert_mode_default": config.cfg.expert_mode_default})
        return st

    @app.get("/api/status")
    def status():
        return full_status()

    @app.get("/api/interfaces")
    def list_ifaces():
        return {"interfaces": interfaces.list_interfaces()}

    @app.post("/api/capture/start")
    def capture_start(body: dict = Body(...)):
        s = engine.start_live(str(body.get("iface", "")), str(body.get("bpf_filter", "") or ""))
        return {"ok": True, "session": s}

    @app.post("/api/capture/stop")
    def capture_stop():
        return {"ok": True, "session": engine.stop()}

    @app.post("/api/capture/import")
    async def capture_import(file: UploadFile = File(...)):
        name = Path(file.filename or "capture.pcap").name
        if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
            raise HTTPException(400, "pcap, pcapng, cap 파일만 분석할 수 있어요.")
        tmp = Path(tempfile.mkdtemp(prefix="netcare-pcap-")) / name
        size = 0
        with tmp.open("wb") as f:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > 500 * (1 << 20):
                    raise HTTPException(400, "500MB 이하 파일만 분석할 수 있어요.")
                f.write(chunk)
        return {"ok": True, "session": engine.import_pcap(tmp, name)}

    @app.get("/api/test/scenarios")
    def scenarios():
        return {"scenarios": [{"id": k, **v} for k, v in synthetic.SCENARIOS.items()]}

    @app.post("/api/test/run")
    def test_run(body: dict = Body(...)):
        return {"ok": True, "session": engine.run_test(str(body.get("scenario", "")))}

    # ───────── 대시보드 / 통계 ─────────
    @app.get("/api/dashboard")
    def dashboard(series: int = Query(120, ge=10, le=3600)):
        snap = engine.stats.snapshot(engine.now() if not (engine.session and engine.session["source"] == "pcap")
                                     else (engine.stats.last_ts or time.time()) + 1, series_sec=series)
        sid = engine.session["id"] if engine.session else None
        anomalies = db.list_anomalies(limit=300)
        cur = [a for a in anomalies if sid is not None and a.get("session_id") == sid]
        live_probe = [a for a in anomalies if a.get("session_id") is None and (not engine.session or engine.session["source"] == "live")]
        relevant = cur + live_probe
        counts = {s: sum(1 for a in relevant if a["severity"] == s) for s in ("danger", "warning", "info")}
        active = sum(1 for a in relevant if a["status"] == "active")
        return {"stats": snap, "health": engine.health, "probe": engine.probe_result, "status": full_status(),
                "anomaly_counts": {**counts, "total": len(relevant), "active": active},
                "recent_anomalies": [{"id": a["id"], "type": a["type"], "type_label": TYPE_LABELS.get(a["type"], a["type"]),
                                      "title": (a.get("explanation") or {}).get("title") or TYPE_LABELS.get(a["type"], a["type"]),
                                      "severity": a["severity"], "status": a["status"], "detected_at": a["detected_at"], "last_seen": a["last_seen"],
                                      "count": a["count"], "ip": a.get("src") or a.get("dst"), "source": a.get("source")} for a in relevant[:8]],
                "activity": _activity(relevant[:12], db.list_actions(limit=8), engine), "names": _names_for(snap, engine)}

    def _names_for(snap, eng):
        ips = {r["ip"] for r in snap["top_src"] + snap["top_dst"]}
        return {ip: eng.names[ip] for ip in ips if ip in eng.names}

    @app.get("/api/stats")
    def stats():
        return engine.snapshot()

    # ───────── 패킷 ─────────
    @app.get("/api/encrypted")
    def encrypted_summary():
        """패킷 분석 화면의 '암호화 통신' 패널: 프로토콜 비율, TLS 버전, SNI 추출률, ECH·PQC, 암호화 DNS, 재조립."""
        return {"summary": engine.enc.snapshot(), "status_labels": {"confirmed": "확인됨", "estimated": "추정됨", "limited": "분석 제한", "failed": "분석 실패"}}

    @app.get("/api/encrypted/events")
    def encrypted_events(kind: str | None = Query(None, pattern=r"^(TLS|QUIC)$"),
                         status: str | None = Query(None, pattern=r"^(confirmed|estimated|limited|failed)$"),
                         limit: int = Query(100, ge=1, le=300)):
        return {"events": engine.enc.recent(kind, status, limit)}

    @app.get("/api/packets")
    def packets(after_id: int = 0, before_id: int | None = None, limit: int = Query(200, ge=1, le=2000),
                proto: str | None = None, q: str | None = None, session_id: int | None = None,
                ip: str | None = None, src: str | None = None, dst: str | None = None, port: int | None = Query(None, ge=0, le=65535),
                sort: str = "id", order: str = "desc", offset: int = Query(0, ge=0), with_total: bool = False,
                tag: str | None = Query(None, pattern=r"^[a-z0-9_]{1,24}$")):
        sid = session_id if session_id is not None else (engine.session["id"] if engine.session else None)
        f = dict(proto=proto or None, q=(q or "").strip() or None, ip=ip or None, src=src or None, dst=dst or None, port=port, tag=tag or None)
        rows = db.list_packets(sid, before_id=before_id, after_id=after_id or None, limit=limit, sort=sort, order=order, offset=offset, **f)
        ctx = engine.context()
        for r in rows:
            r["src_label"] = terms.describe_ip(r["src"], ctx["local_ips"], engine.names)
            r["dst_label"] = terms.describe_ip(r["dst"], ctx["local_ips"], engine.names)
        out = {"packets": rows, "session_id": sid}
        if with_total:
            out["total"] = db.count_packets(sid, **f)
        return out

    @app.get("/api/ip/{ip}")
    def ip_detail(ip: str):
        ctx = engine.context()
        sid = engine.session["id"] if engine.session else None
        d = db.ip_summary(ip, sid)
        d["label"] = terms.describe_ip(ip, ctx["local_ips"], engine.names)
        d["is_local"] = ip in ctx["local_ips"]
        d["is_gateway"] = ip == ctx.get("gateway")
        d["is_dns_server"] = ip in (ctx.get("dns_servers") or [])
        d["whitelisted"] = ip in config.cfg.detection.whitelist
        d["name"] = d["name"] or engine.names.get(ip)
        d["scope"] = "session" if sid is not None else "all"
        for a in d["anomalies"]:
            a["type_label"] = TYPE_LABELS.get(a["type"], a["type"])
            a["title"] = (a.get("explanation") or {}).get("title") or a["type_label"]
            a.pop("explanation", None)
        return d

    @app.get("/api/search")
    def search(q: str = Query(..., min_length=1, max_length=80)):
        q = q.strip()
        r = db.search(q)
        ctx = engine.context()
        for x in r["ips"]:
            x["label"] = terms.describe_ip(x["ip"], ctx["local_ips"], engine.names)
        for a in r["anomalies"]:
            a["type_label"] = TYPE_LABELS.get(a["type"], a["type"])
            a["title"] = (a.get("explanation") or {}).get("title") or a["type_label"]
            a.pop("explanation", None)
        ports = []
        if q.isdigit() and 0 <= int(q) <= 65535:
            ports.append({"port": int(q), "label": terms.describe_port(int(q)) if hasattr(terms, "describe_port") else f"포트 {q}"})
        r["ports"] = ports
        r["rules"] = [{"type": t, "label": l} for t, l in TYPE_LABELS.items() if q.lower() in l.lower() or q.lower() in t][:6]
        return r

    @app.get("/api/packets/{pid}")
    def packet_detail(pid: int):
        p = db.get_packet(pid)
        if not p:
            raise HTTPException(404, "패킷을 찾을 수 없어요 (보존 한도를 넘어 삭제됐을 수 있어요).")
        raw = p.pop("raw", None)
        tree = dissect(raw, p["first_layer"]) if raw else {"layers": [], "hex": [], "total": 0,
                                                           "note": "원본 저장이 꺼져 있어 상세 헤더를 볼 수 없어요."}
        ctx = engine.context()
        p["src_label"] = terms.describe_ip(p["src"], ctx["local_ips"], engine.names)
        p["dst_label"] = terms.describe_ip(p["dst"], ctx["local_ips"], engine.names)
        p["src_domain"], p["dst_domain"] = engine.names.get(p["src"]), engine.names.get(p["dst"])
        name, desc, port = terms.service_for(p["proto"], p["sport"], p["dport"])
        p["service_desc"] = desc or terms.PROTOCOLS.get(p["proto"], "")
        p["protocol_desc"] = terms.PROTOCOLS.get(p["proto"], "")
        p["truncated"] = bool(raw) and len(raw) < p["length"]
        # 이 패킷에서 끝난 암호화 통신 분석(TCP 재조립·QUIC Initial)이 있으면 함께 (전문가 모드 상세)
        enc = next((e for e in engine.enc.recent(limit=300) if e.get("packet_id") == pid), None)
        return {"packet": p, "tree": tree, "encrypted": enc}

    # ───────── 이상 징후 ─────────
    @app.get("/api/anomalies")
    def anomalies(status: str | None = None, limit: int = Query(200, ge=1, le=2000), scope: str = "all"):
        rows = db.list_anomalies(status=status or None, limit=limit)
        if scope == "session" and engine.session:
            rows = [r for r in rows if r.get("session_id") in (engine.session["id"], None)]
        for r in rows:
            r["type_label"] = TYPE_LABELS.get(r["type"], r["type"])
        return {"anomalies": rows}

    @app.get("/api/anomalies/{aid}")
    def anomaly(aid: int):
        a = db.get_anomaly(aid)
        if not a:
            raise HTTPException(404, "이상 징후를 찾을 수 없어요.")
        if not a.get("explanation"):
            a["explanation"] = explain(a, engine.context())
        a["type_label"] = TYPE_LABELS.get(a["type"], a["type"])
        a["actions"] = db.list_actions(anomaly_id=aid)
        return a

    @app.post("/api/anomalies/{aid}/dismiss")
    def dismiss(aid: int, body: dict = Body(default={})):
        a = db.get_anomaly(aid)
        if not a:
            raise HTTPException(404, "이상 징후를 찾을 수 없어요.")
        db.update_row("anomalies", aid, {"status": "dismissed"})
        added = None
        if body.get("whitelist"):
            ip = a.get("src") or a.get("dst")
            if ip:
                wl = list(config.cfg.detection.whitelist)
                if ip not in wl:
                    wl.append(ip)
                    config.update({"detection": {"whitelist": wl}})
                    engine.detector.set_config(config.cfg.detection)
                added = ip
        return {"ok": True, "whitelisted": added}

    # ───────── 조치 ─────────
    @app.get("/api/rules")
    def rules():
        return {"rules": rule_catalog(config.cfg.detection), "note": "임계값은 현재 설정값이에요. 설정에서 바꾸면 여기에도 반영돼요."}

    @app.get("/api/rules/{rtype}")
    def rule(rtype: str):
        for r in rule_catalog(config.cfg.detection):
            if r["type"] == rtype:
                return r
        raise HTTPException(404, "그런 탐지 규칙이 없어요.")

    @app.get("/api/actions/catalog")
    def catalog():
        return engine.actions.catalog()

    @app.post("/api/actions/preview")
    def preview(body: dict = Body(...)):
        return engine.actions.preview(body.get("action", ""), body.get("params") or {}, body.get("anomaly_id"))

    @app.post("/api/actions/execute")
    def execute(body: dict = Body(...)):
        return engine.actions.execute(body.get("action", ""), body.get("params") or {}, body.get("anomaly_id"),
                                      confirm=bool(body.get("confirm")), acknowledge_risk=bool(body.get("acknowledge_risk")),
                                      elevate=bool(body.get("elevate")))

    @app.post("/api/actions/{action_id}/verify")
    def verify(action_id: int):
        return engine.actions.verify(action_id)

    @app.post("/api/actions/{action_id}/rollback")
    def rollback(action_id: int, body: dict = Body(default={})):
        return engine.actions.rollback(action_id, confirm=bool(body.get("confirm")), elevate=bool(body.get("elevate")))

    @app.get("/api/actions")
    def actions(limit: int = Query(100, ge=1, le=1000)):
        rows = db.list_actions(limit=limit)
        for r in rows:
            r["title"] = CATALOG.get(r["action"], {}).get("title", r["action"])
        return {"actions": rows}

    # ───────── 점검 ─────────
    @app.post("/api/probe/run")
    def probe_run():
        return {"probe": engine.run_probe_now(), "health": engine.health}

    # ───────── 설정 ─────────
    @app.get("/api/settings")
    def get_settings():
        return config.as_dict()

    @app.put("/api/settings")
    def put_settings(body: dict = Body(...)):
        if body.get("auto_block_enabled") and not config.cfg.auto_block_enabled and body.get("auto_block_consent") is not True:
            raise HTTPException(400, "자동 차단을 켜려면 경고 내용에 동의해야 해요.")
        body.pop("auto_block_consent", None)
        try:
            cfg = config.update(body)
        except ValueError as e:
            raise HTTPException(400, str(e))
        engine.detector.set_config(cfg.detection)
        return config.as_dict()

    # ───────── 리포트 / 내보내기 ─────────
    def _range(days: int | None, start: str | None, end: str | None) -> tuple[float, float]:
        if start:
            try:
                s = datetime.strptime(start, "%Y-%m-%d")
                e = datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1) if end else s + timedelta(days=1)
            except ValueError:
                raise HTTPException(400, "날짜 형식은 YYYY-MM-DD 예요.")
            return s.timestamp(), e.timestamp()
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        d = max(1, min(int(days or 7), 365))
        return (today - timedelta(days=d - 1)).timestamp(), (today + timedelta(days=1)).timestamp()

    @app.get("/api/report")
    def report(days: int | None = 7, start: str | None = None, end: str | None = None, include_test: bool = False):
        s, e = _range(days, start, end)
        r = db.report(s, e, include_test)
        for a in r["anomalies"]:
            a["type_label"] = TYPE_LABELS.get(a["type"], a["type"])
            a.pop("explanation", None)
        for row in r["top_src"] + r["top_dst"]:
            row["label"] = terms.describe_ip(row["ip"], engine.local_ips, engine.names)
        r["range"] = {"start": s, "end": e, "include_test": include_test}
        return r

    @app.get("/api/export/{kind}.csv")
    def export_csv(kind: str, days: int | None = 7, start: str | None = None, end: str | None = None, include_test: bool = False):
        if kind not in ("packets", "traffic", "anomalies", "actions", "health"):
            raise HTTPException(404, "알 수 없는 내보내기 종류예요.")
        s, e = _range(days, start, end)
        data = export.to_csv(kind, db.export_rows(kind, s, e, include_test))
        fn = f"netcare_{kind}_{datetime.now():%Y%m%d_%H%M}.csv"
        return Response(data, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{fn}"'})

    @app.get("/api/export/report.pdf")
    def export_pdf(days: int | None = 7, start: str | None = None, end: str | None = None, include_test: bool = False):
        s, e = _range(days, start, end)
        try:
            data = export.to_pdf(db.report(s, e, include_test), s, e, include_test)
        except RuntimeError as ex:
            raise HTTPException(500, str(ex))
        fn = f"netcare_report_{datetime.now():%Y%m%d_%H%M}.pdf"
        return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{fn}"'})

    # ───────── Simulation Lab (가상 실험실) ─────────
    def _lab_call(fn, *a, **k):
        try:
            return fn(*a, **k)
        except (ValueError, RuntimeError) as e:
            raise HTTPException(400, str(e))

    @app.get("/api/lab/scenarios")
    def lab_scenarios():
        return {"scenarios": lab.scenarios(), "actions": lab.actions.catalog()["actions"],
                "note": "합성 데이터로 만든 가상 패킷이에요. 실제 네트워크로 전송하지 않고, 실제 방화벽·설정도 바꾸지 않아요."}

    @app.post("/api/lab/run")
    def lab_run(body: dict = Body(...)):
        eid = _lab_call(lab.start, str(body.get("scenario", "")), body.get("params") or {}, str(body.get("policy") or "none"),
                        bool(body.get("realtime")))
        return {"ok": True, "experiment_id": eid}

    @app.post("/api/lab/stop")
    def lab_stop():
        lab.stop()
        return {"ok": True}

    @app.post("/api/lab/pause")
    def lab_pause(body: dict = Body(default={})):
        return {"ok": True, "paused": lab.pause(body.get("paused"))}

    @app.get("/api/lab/status")
    def lab_status():
        st = lab.status()
        st["engine"] = {"state": lab.engine.state, "processed": lab.engine.processed, "dropped": lab.engine.dropped}
        if lab.current:
            st["stats"] = lab.engine.snapshot()
        return st

    @app.get("/api/lab/experiments")
    def lab_experiments(limit: int = Query(100, ge=1, le=1000), benchmark_id: int | None = None):
        return {"experiments": lab.experiments(limit, benchmark_id)}

    @app.get("/api/lab/experiments/{eid}")
    def lab_experiment(eid: int):
        e = lab.experiment(eid)
        if not e:
            raise HTTPException(404, "실험을 찾을 수 없어요.")
        for a in e.get("anomalies") or []:
            a["type_label"] = TYPE_LABELS.get(a["type"], a["type"])
        return e

    @app.get("/api/lab/experiments/{eid}/pcap")
    def lab_pcap(eid: int):
        e = lab.experiment(eid)
        if not e or not e.get("pcap_path") or not Path(e["pcap_path"]).exists():
            raise HTTPException(404, "PCAP 파일이 없어요.")
        return FileResponse(e["pcap_path"], media_type="application/vnd.tcpdump.pcap",
                            filename=f"netcare_sim_{e['scenario']}_exp{eid}.pcap")

    @app.post("/api/lab/actions/execute")
    def lab_action(body: dict = Body(...)):
        return _lab_call(lab.actions.execute, str(body.get("action", "")), body.get("params") or {}, "user", body.get("anomaly_id"))

    @app.post("/api/lab/benchmark")
    def lab_benchmark(body: dict = Body(default={})):
        bid = _lab_call(lab.start_benchmark, body.get("scenarios"), body.get("intensities"), body.get("seeds"))
        return {"ok": True, "benchmark_id": bid}

    @app.get("/api/lab/benchmarks")
    def lab_benchmarks():
        return {"benchmarks": lab.benchmarks()}

    @app.get("/api/lab/benchmarks/{bid}")
    def lab_benchmark_detail(bid: int):
        row = lab.db.query_one("SELECT * FROM benchmarks WHERE id=?", (bid,))
        if not row:
            raise HTTPException(404, "벤치마크를 찾을 수 없어요.")
        if not row.get("summary"):
            row["summary"] = lab.benchmark_summary(bid)
        for r in row["summary"]["by_scenario"]:
            from netcare.simlab.scenarios import SCENARIOS as _SC
            r["title"] = _SC[r["scenario"]].title if r["scenario"] in _SC else r["scenario"]
        return row

    @app.get("/api/lab/packets")
    def lab_packets(experiment_id: int, after_id: int = 0, limit: int = Query(200, ge=1, le=2000), q: str | None = None):
        e = lab.db.query_one("SELECT session_id FROM experiments WHERE id=?", (experiment_id,))
        if not e or not e.get("session_id"):
            return {"packets": []}
        rows = lab.db.list_packets(e["session_id"], limit=limit, q=(q or "").strip() or None)
        if after_id:
            rows = [r for r in rows if r["id"] > after_id]
        from netcare.simlab import network as _N
        for r in rows:
            r["src_label"] = terms.describe_ip(r["src"], {_N.CLIENT_IP}, {})
            r["dst_label"] = terms.describe_ip(r["dst"], {_N.CLIENT_IP}, {})
        return {"packets": rows}

    @app.get("/api/lab/packets/{pid}")
    def lab_packet(pid: int):
        p = lab.db.get_packet(pid)
        if not p:
            raise HTTPException(404, "패킷을 찾을 수 없어요.")
        raw = p.pop("raw", None)
        from netcare.simlab import network as _N
        p["src_label"] = terms.describe_ip(p["src"], {_N.CLIENT_IP}, {})
        p["dst_label"] = terms.describe_ip(p["dst"], {_N.CLIENT_IP}, {})
        p["service_desc"] = terms.service_for(p["proto"], p["sport"], p["dport"])[1] or terms.PROTOCOLS.get(p["proto"], "")
        p["protocol_desc"] = terms.PROTOCOLS.get(p["proto"], "")
        p["truncated"] = False
        return {"packet": p, "tree": dissect(raw, p["first_layer"]) if raw else {"layers": [], "hex": []}}

    @app.get("/api/lab/export/experiments.csv")
    def lab_export():
        rows = lab.experiments(100000)
        data = export.to_csv("lab", rows)
        return Response(data, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="netcare_simlab_{datetime.now():%Y%m%d_%H%M}.csv"'})

    return app


def _activity(anoms: list[dict], acts: list[dict], engine: Engine) -> list[dict]:
    """홈 화면 '최근 네트워크 활동' (실제 이벤트만)."""
    items = []
    for a in anoms:
        exp = a.get("explanation") or {}
        items.append({"ts": a["last_seen"], "kind": "anomaly", "severity": a["severity"], "id": a["id"],
                      "text": exp.get("title") or TYPE_LABELS.get(a["type"], a["type"]), "source": a.get("source"),
                      "status": a["status"]})
    for x in acts:
        items.append({"ts": x["created_at"], "kind": "action", "severity": "good" if x["status"] in ("success", "simulated") else "warning",
                      "id": x["id"], "anomaly_id": x.get("anomaly_id"),
                      "text": f"{CATALOG.get(x['action'], {}).get('title', x['action'])} · {_status_ko(x['status'])}"})
    s = engine.session
    if s:
        items.append({"ts": s["started"], "kind": "session", "severity": "info", "text": f"{s['title']} 시작", "source": s["source"]})
        if s.get("ended"):
            items.append({"ts": s["ended"], "kind": "session", "severity": "info", "text": f"{s['title']} 종료", "source": s["source"]})
    items.sort(key=lambda i: -i["ts"])
    return items[:15]


def _status_ko(s: str) -> str:
    return {"success": "완료", "failed": "실패", "simulated": "시뮬레이션", "running": "실행 중", "cancelled": "취소",
            "rolled_back": "되돌림"}.get(s, s)
