"""API 통합 테스트: 보안 미들웨어, pcap 가져오기(테스트 데이터로 만든 파일), 조치 안전장치, 내보내기."""
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.utils import wrpcap

from netcare.api.server import create_app
from netcare.testdata import synthetic

H = {"X-NetCare": "1"}


@pytest.fixture(scope="module")
def client():
    d = tempfile.mkdtemp(prefix="netcare-api-")
    app = create_app(Path(d), start_probe=False)
    with TestClient(app) as c:
        yield c


def _scenario_pcap(name: str) -> Path:
    pkts, t0 = [], 1_700_000_000.0
    for sec, batch in synthetic.generate(name):
        for i, p in enumerate(batch):
            p.time = t0 + sec + i / (len(batch) + 1)
            pkts.append(p)
    path = Path(tempfile.mkdtemp()) / f"{name}.pcap"
    wrpcap(str(path), pkts)
    return path


def _wait_idle(c, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if c.get("/api/status").json()["state"] == "idle":
            return
        time.sleep(0.3)
    raise AssertionError("분석이 끝나지 않음")


def test_security_headers_and_host(client):
    assert client.post("/api/capture/stop").status_code == 403              # 커스텀 헤더 없음
    assert client.get("/api/status", headers={"Host": "evil.example"}).status_code == 403  # DNS 리바인딩 방지
    assert client.get("/api/status").status_code == 200


def test_bad_filter_and_iface(client):
    r = client.post("/api/capture/start", json={"iface": "nonexistent0"}, headers=H)
    assert r.status_code == 400 and r.json()["code"] == "no_iface"


def test_pcap_import_detects_port_scan(client):
    path = _scenario_pcap("port_scan")
    with path.open("rb") as f:
        r = client.post("/api/capture/import", files={"file": ("scan.pcap", f, "application/octet-stream")}, headers=H)
    assert r.status_code == 200, r.text
    _wait_idle(client)
    st = client.get("/api/status").json()
    assert st["session"]["source"] == "pcap" and st["processed"] > 0
    an = client.get("/api/anomalies").json()["anomalies"]
    scans = [a for a in an if a["type"] == "port_scan" and a["source"] == "pcap"]
    assert scans and scans[0]["src"] == "198.51.100.23"
    dash = client.get("/api/dashboard").json()
    assert dash["stats"]["total_packets"] == st["processed"]   # 통계는 처리한 패킷 수와 정확히 일치
    pk = client.get("/api/packets?limit=5").json()["packets"]
    det = client.get(f"/api/packets/{pk[0]['id']}").json()
    assert det["tree"]["layers"]


def test_reject_non_pcap_upload(client):
    r = client.post("/api/capture/import", files={"file": ("x.txt", b"hello", "text/plain")}, headers=H)
    assert r.status_code == 400


def test_action_safety_rules(client):
    an = client.get("/api/anomalies").json()["anomalies"]
    aid = next(a["id"] for a in an if a["type"] == "port_scan")
    # pcap(실제 기록) 출처 징후는 시뮬레이션이 아님 → 관리자 권한 없으면 needs_admin
    r = client.post("/api/actions/execute", json={"action": "block_ip", "params": {"ip": "198.51.100.23"}, "anomaly_id": aid}, headers=H)
    assert r.status_code == 400 and r.json()["code"] == "confirmation_required"
    pv = client.post("/api/actions/preview", json={"action": "block_ip", "params": {"ip": "198.51.100.23"}, "anomaly_id": aid}, headers=H).json()
    assert pv["simulated"] is False and pv["commands"]
    # 보호 IP 는 차단 거부
    for ip in ("127.0.0.1", "224.0.0.251", "255.255.255.255"):
        pv = client.post("/api/actions/preview", json={"action": "block_ip", "params": {"ip": ip}}, headers=H).json()
        assert pv["blocked_reason"], ip
    r = client.post("/api/actions/preview", json={"action": "block_ip", "params": {"ip": "not-an-ip"}}, headers=H)
    assert r.status_code >= 400
    r = client.post("/api/actions/execute", json={"action": "rm_rf", "params": {}}, headers=H)
    assert r.status_code == 400 and r.json()["code"] == "unknown_action"


def test_safe_actions_run(client):
    r = client.post("/api/actions/execute", json={"action": "inspect_ip", "params": {"ip": "198.51.100.23"}}, headers=H).json()
    assert r["status"] == "success" and r["result"]["summary"]["packets"] > 0
    r = client.post("/api/actions/execute", json={"action": "find_process", "params": {"port": 443}}, headers=H).json()
    assert r["status"] == "success" and "message" in r["result"]


def test_settings_validation_and_autoblock_consent(client):
    assert client.put("/api/settings", json={"detection": {"syn_threshold": -5}}, headers=H).status_code == 400
    assert client.put("/api/settings", json={"detection": {"whitelist": ["bad ip"]}}, headers=H).status_code == 400
    assert client.put("/api/settings", json={"auto_block_enabled": True}, headers=H).status_code == 400
    assert client.get("/api/settings").json()["auto_block_enabled"] is False
    r = client.put("/api/settings", json={"detection": {"syn_threshold": 80}}, headers=H)
    assert r.status_code == 200 and r.json()["detection"]["syn_threshold"] == 80


def test_dismiss_adds_whitelist(client):
    an = client.get("/api/anomalies").json()["anomalies"]
    a = next(x for x in an if x["src"])
    r = client.post(f"/api/anomalies/{a['id']}/dismiss", json={"whitelist": True}, headers=H).json()
    assert r["whitelisted"] == a["src"]
    assert a["src"] in client.get("/api/settings").json()["detection"]["whitelist"]


def test_report_and_exports(client):
    r = client.get("/api/report?start=2023-11-01&end=2023-11-30&include_test=true").json()
    assert r["protocols"]["total"] > 0
    live_only = client.get("/api/report?start=2023-11-01&end=2023-11-30").json()
    assert live_only["protocols"]["total"] == 0           # 파일/테스트 데이터는 기본 리포트에서 제외
    for kind in ("packets", "traffic", "anomalies", "actions", "health"):
        c = client.get(f"/api/export/{kind}.csv?start=2023-11-01&end=2023-11-30&include_test=true")
        assert c.status_code == 200 and c.content.startswith("﻿".encode())
    pdf = client.get("/api/export/report.pdf?start=2023-11-01&end=2023-11-30&include_test=true")
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"
