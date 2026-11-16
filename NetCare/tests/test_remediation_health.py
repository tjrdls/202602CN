"""조치 안전 규칙, 방화벽 명령 생성, 건강 점수, 설정 검증 단위 테스트."""
import pytest

from netcare.analysis import health, probe
from netcare.config import AppConfig, ConfigStore, validate
from netcare.remediation import system
from netcare.remediation.firewall import LinuxIptables, MacPF, WindowsNetsh


def test_protection_reasons():
    ctx = {"local_ips": {"192.168.0.10"}, "gateway": "192.168.0.1", "dns_servers": ["8.8.8.8"], "whitelist": ["203.0.113.0/24"]}
    assert "내 컴퓨터" in system.protection_reason("192.168.0.10", ctx)
    assert "게이트웨이" in system.protection_reason("192.168.0.1", ctx)
    assert "DNS" in system.protection_reason("8.8.8.8", ctx)
    assert "화이트리스트" in system.protection_reason("203.0.113.7", ctx)
    assert system.protection_reason("fe80::1", ctx)
    assert system.protection_reason("198.51.100.5", ctx) is None


def test_normalize_ip_rejects_injection():
    with pytest.raises(ValueError):
        system.normalize_ip("1.2.3.4; rm -rf /")
    assert system.normalize_ip(" 2001:db8::1 ") == "2001:db8::1"


@pytest.mark.parametrize("backend", [MacPF(), LinuxIptables(), WindowsNetsh()])
def test_firewall_scripts_only_touch_netcare_rules(backend):
    lines = backend.block_script("198.51.100.5")
    joined = "\n".join(lines)
    assert "198.51.100.5" in joined
    assert any(tag in joined for tag in ("com.apple/netcare", "NetCare"))
    un = "\n".join(backend.unblock_script("198.51.100.5", {"pf_token": "123"}))
    assert "198.51.100.5" in un


def test_pf_output_parsing_and_rollback_info():
    out = "##BEFORE_STATUS\nStatus: Disabled for 0 days\n##BEFORE_TABLE\n\n##LOAD\n\n##ENABLE\npf enabled\nToken : 1234567\n##ADD\n1/1 addresses added.\n##KILL\n\n##AFTER_TABLE\n   198.51.100.5\n"
    p = MacPF().parse_block_output("198.51.100.5", out)
    assert p["applied"] and p["rollback_info"]["pf_token"] == "1234567" and p["rollback_info"]["pf_was_enabled"] is False
    un = MacPF().unblock_script("198.51.100.5", p["rollback_info"])
    assert any("pfctl -X 1234567" in ln for ln in un)   # NetCare 가 켠 pf 는 토큰 반납으로 원상복구


def test_health_score_rules():
    h = health.compute([], None)
    assert h["score"] == 100 and h["measured_items"] == 1   # 측정 안 한 항목은 감점 없음
    an = [{"status": "active", "severity": "danger", "last_seen": 9e9}, {"status": "active", "severity": "warning", "last_seen": 9e9}]
    pr = {"gateway": {"target": "gw", "sent": 4, "received": 2, "loss_pct": 50.0, "avg_ms": 5}, "external": None,
          "dns": {"tested": 2, "failed": 1, "avg_ms": 20, "results": []}}
    h = health.compute(an, pr, now=9e9)
    assert h["score"] == 100 - 35 - 20 - 10 and h["status"] == "danger"   # 35점 → 위험(50 미만)


def test_ping_parsers():
    mac = "4 packets transmitted, 3 packets received, 25.0% packet loss\nround-trip min/avg/max/stddev = 1.1/2.2/3.3/0.4 ms"
    r = probe.parse_ping_output(mac, 4)
    assert r["loss_pct"] == 25.0 and r["avg_ms"] == 2.2
    win = "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\nMinimum = 1ms, Maximum = 3ms, Average = 2ms"
    r = probe.parse_ping_output(win, 4)
    assert r["loss_pct"] == 0 and r["avg_ms"] == 2.0


def test_config_validation(tmp_path):
    cfg = AppConfig()
    validate(cfg)
    cfg.detection.port_share_threshold = 1.5
    with pytest.raises(ValueError):
        validate(cfg)
    store = ConfigStore(tmp_path / "c.json")
    with pytest.raises(ValueError):
        store.update({"detection": {"window_sec": 0}})
    assert store.cfg.detection.window_sec == 10      # 실패 시 이전 값 유지
    assert store.cfg.auto_block_enabled is False      # 자동 차단 기본 비활성
