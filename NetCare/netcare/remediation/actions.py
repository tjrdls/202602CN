"""조치 카탈로그와 '승인 → 실행 → 검증 → 롤백' 흐름.

안전 원칙
1. 시스템을 바꾸는 조치(changes_system=True)는 confirm 과 acknowledge_risk 가 모두 True 여야 실행한다.
2. 보호 대상 IP(내 주소, 게이트웨이, DNS 서버, 특수 주소, 화이트리스트)는 차단을 거부한다.
3. 관리자 권한이 없으면 실행하지 않고, 직접 실행할 명령과 방법을 안내한다.
   (macOS 는 사용자가 원하면 OS 관리자 암호 창으로 실행 가능)
4. 실행 전 상태와 롤백 정보를 DB 에 기록한다.
5. 테스트 데이터에서 나온 징후로는 시스템을 바꾸지 않고 시뮬레이션만 한다.
6. 자동 차단은 기본 비활성. 켜져 있어도 엄격한 조건 + 만료 시간 후 자동 해제.
"""
from __future__ import annotations

import ipaddress
import json
import shlex
import time
from typing import Callable

import psutil

from netcare.analysis import probe, terms
from netcare.remediation import system
from netcare.remediation.firewall import get_backend

CATALOG = {
    "connectivity_check": {
        "title": "인터넷 연결 상태 점검", "icon": "pulse",
        "description": "공유기(게이트웨이)와 외부 인터넷에 확인 신호(ping)를 보내 응답 시간과 손실률을 재고, DNS 조회도 함께 테스트해요.",
        "side_effects": "확인용 패킷을 몇 개 보낼 뿐이라 설정은 바뀌지 않아요.",
        "requires_admin": False, "changes_system": False, "reversible": False, "risk": "none",
    },
    "dns_test": {
        "title": "DNS 조회 테스트", "icon": "search",
        "description": "주요 웹사이트 주소를 실제로 조회해서 성공 여부와 걸린 시간을 확인해요.",
        "side_effects": "없음 (조회만 해요).",
        "requires_admin": False, "changes_system": False, "reversible": False, "risk": "none",
    },
    "flush_dns": {
        "title": "DNS 캐시 초기화", "icon": "refresh",
        "description": "컴퓨터에 저장된 도메인 주소 기록을 지워서, 잘못된 기록 대신 새로 조회하게 해요. 초기화 전후로 DNS 조회 테스트를 해서 결과를 비교해요.",
        "side_effects": "처음 접속하는 사이트가 잠깐(수십 ms) 느리게 열릴 수 있어요. 지운 기록은 자동으로 다시 쌓이므로 되돌릴 필요가 없어요.",
        "requires_admin": system.SYSTEM in ("Darwin", "Linux"), "changes_system": True, "reversible": False, "risk": "low",
    },
    "inspect_ip": {
        "title": "통신 내역 확인", "icon": "list",
        "description": "저장된 패킷에서 이 장치와 언제, 어떤 서비스로, 얼마나 통신했는지 정리해요.",
        "side_effects": "없음 (저장된 기록만 읽어요).",
        "requires_admin": False, "changes_system": False, "reversible": False, "risk": "none",
    },
    "find_process": {
        "title": "통신 중인 프로그램 찾기", "icon": "app",
        "description": "운영체제에 현재 열린 네트워크 연결을 물어서 어떤 프로그램(프로세스)이 통신하는지 보여줘요.",
        "side_effects": "없음. 관리자 권한이 없으면 내 계정으로 실행 중인 프로그램만 보여요.",
        "requires_admin": False, "changes_system": False, "reversible": False, "risk": "none",
    },
    "block_ip": {
        "title": "방화벽으로 IP 차단", "icon": "shield",
        "description": "운영체제 방화벽에 NetCare 전용 규칙을 추가해서 이 IP와 주고받는 모든 통신을 막아요.",
        "side_effects": "이 IP를 쓰는 웹사이트·앱·기기와의 통신이 모두 끊겨요. 하나의 IP를 여러 서비스가 함께 쓰는 경우(CDN 등) 다른 사이트도 안 열릴 수 있어요. '되돌리기'로 언제든 해제할 수 있어요.",
        "requires_admin": True, "changes_system": True, "reversible": True, "risk": "high",
    },
}


class ActionError(Exception):
    def __init__(self, message: str, code: str = "error", extra: dict | None = None):
        super().__init__(message)
        self.code = code
        self.extra = extra or {}


class ActionManager:
    AUTO_BLOCK_TYPES = {"syn_surge", "port_scan", "ip_packet_flood"}

    def __init__(self, db, ctx_provider: Callable[[], dict], config_provider: Callable):
        self.db = db
        self.ctx = ctx_provider
        self.cfg = config_provider
        self.fw = get_backend()

    # ───────── 카탈로그 / 미리보기 ─────────
    def catalog(self) -> dict:
        return {"actions": CATALOG, "is_admin": system.is_admin(), "can_elevate": system.can_elevate(),
                "platform": system.SYSTEM, "firewall": {"name": self.fw.name, "label": self.fw.label, "available": self.fw.available()},
                "auto_block_enabled": self.cfg().auto_block_enabled}

    def _anomaly(self, anomaly_id):
        if anomaly_id is None:
            return None
        a = self.db.get_anomaly(int(anomaly_id))
        if a is None:
            raise ActionError("해당 이상 징후를 찾을 수 없어요.", "not_found")
        return a

    def _dns_flush_cmd(self) -> list[str]:
        if system.SYSTEM == "Darwin":
            return ["dscacheutil -flushcache", "killall -HUP mDNSResponder"]
        if system.SYSTEM == "Windows":
            return ["ipconfig /flushdns"]
        return ["resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null || (echo 'systemd-resolved 가 없어요'; exit 1)"]

    def preview(self, action: str, params: dict | None, anomaly_id=None) -> dict:
        spec = CATALOG.get(action)
        if not spec:
            raise ActionError(f"알 수 없는 조치예요: {action}", "unknown_action")
        params = dict(params or {})
        anomaly = self._anomaly(anomaly_id)
        simulated = bool(anomaly and anomaly.get("source") == "test")
        warnings, commands, blocked_reason = [], [], None
        if action == "block_ip":
            try:
                ip = system.normalize_ip(params.get("ip", ""))
            except ValueError as e:
                raise ActionError(str(e), "invalid_ip")
            params["ip"] = ip
            ctx = self.ctx()
            blocked_reason = system.protection_reason(ip, {**ctx, "whitelist": self.cfg().detection.whitelist})
            if not self.fw.available():
                import os
                blocked_reason = blocked_reason or ("도커 컨테이너에서는 호스트 방화벽을 바꾸지 않아요. 차단이 필요하면 호스트에서 직접 실행해 주세요."
                                                    if os.environ.get("NETCARE_CONTAINER") == "1" else "이 운영체제에서는 자동 방화벽 조치를 지원하지 않아요.")
            if not blocked_reason:
                commands = self.fw.block_script(ip)
                if terms.ip_scope(ip) == "local":
                    warnings.append("같은 네트워크(사설망)에 있는 장치예요. 차단하면 이 장치(프린터, NAS, 다른 PC 등)와 통신할 수 없어요.")
                names = ctx.get("names") or {}
                if ip in names:
                    warnings.append(f"이 IP는 '{names[ip]}' 도메인으로 확인됐어요. 이 사이트(또는 같은 IP를 쓰는 다른 사이트)가 열리지 않게 돼요.")
                warnings.append("방화벽 규칙을 바꾸는 작업이에요. 정상 통신을 잘못 차단하지 않도록, 먼저 '통신 내역 확인'과 '프로그램 찾기'로 확인해 보세요.")
        elif action == "flush_dns":
            commands = self._dns_flush_cmd()
        elif action == "connectivity_check":
            ctx = self.ctx()
            pc = self.cfg().probe
            commands = [f"ping {ctx.get('gateway') or '(게이트웨이 없음)'}", f"ping {pc.external_target}"] + \
                       ([f"ping {params['target']}"] if params.get("target") else []) + [f"DNS 조회: {', '.join(pc.dns_test_domains)}"]
        elif action == "dns_test":
            commands = [f"DNS 조회: {', '.join(self.cfg().probe.dns_test_domains)}"]
        elif action == "find_process":
            commands = ["psutil.net_connections() (권한 부족 시 lsof -nP -i)"]
        elif action == "inspect_ip":
            commands = ["저장된 패킷 DB 조회"]
        needs_admin = spec["requires_admin"] and not system.is_admin() and not simulated
        return {"action": action, "spec": spec, "params": params, "commands": commands, "warnings": warnings,
                "blocked_reason": blocked_reason, "simulated": simulated, "needs_admin": needs_admin,
                "is_admin": system.is_admin(), "can_elevate": system.can_elevate() and needs_admin,
                "manual_command": self._manual(commands) if needs_admin else None}

    @staticmethod
    def _manual(commands: list[str]) -> str:
        if system.SYSTEM == "Windows":
            return "관리자 권한 명령 프롬프트에서 실행:\n" + "\n".join(c for c in commands if not c.startswith("echo"))
        body = "\n".join(c for c in commands if not c.startswith("echo"))
        return "터미널에서 실행 (관리자 암호 필요):\nsudo sh -c " + shlex.quote(body)

    # ───────── 실행 ─────────
    def execute(self, action: str, params: dict | None, anomaly_id=None, confirm: bool = False,
                acknowledge_risk: bool = False, elevate: bool = False, trigger: str = "user") -> dict:
        pv = self.preview(action, params, anomaly_id)
        spec, params = pv["spec"], pv["params"]
        if pv["blocked_reason"]:
            raise ActionError(pv["blocked_reason"], "protected")
        if spec["changes_system"] and not (confirm and acknowledge_risk):
            raise ActionError("시스템 설정을 바꾸는 조치는 내용과 부작용을 확인하고 동의해야 실행돼요.", "confirmation_required")
        if pv["needs_admin"] and not elevate:
            raise ActionError("이 조치는 관리자 권한이 필요해요.", "needs_admin",
                              {"manual_command": pv["manual_command"], "can_elevate": pv["can_elevate"]})
        if elevate and not system.can_elevate():
            elevate = False

        rec = {"created_at": time.time(), "anomaly_id": anomaly_id, "action": action, "params": params,
               "trigger": trigger, "status": "running", "simulated": 1 if pv["simulated"] else 0}
        aid = self.db.insert_action(rec)
        try:
            if pv["simulated"] and spec["changes_system"]:
                out = {"status": "simulated", "result": {"message": "테스트 데이터에서 나온 징후라 실제 시스템은 바꾸지 않았어요. 실제였다면 아래 명령이 실행됐을 거예요.",
                                                         "commands": pv["commands"]},
                       "rollback_info": {"simulated": True, "ip": params.get("ip")} if spec["reversible"] else None}
            else:
                out = getattr(self, f"_do_{action}")(params, elevate)
        except ActionError:
            self.db.update_row("actions", aid, {"status": "failed", "result": {"message": "실행 중 오류"}})
            raise
        except Exception as e:  # 예기치 못한 오류도 기록
            self.db.update_row("actions", aid, {"status": "failed", "result": {"message": f"실행 중 오류: {e}"}})
            raise ActionError(f"실행 중 오류가 발생했어요: {e}")
        upd = {"status": out["status"], "result": out.get("result"), "before_state": out.get("before_state"),
               "rollback_info": out.get("rollback_info"), "verification": out.get("verification")}
        if trigger == "auto" and out["status"] == "success":
            upd["expires_at"] = time.time() + self.cfg().auto_block_ttl_min * 60
        self.db.update_row("actions", aid, upd)
        if anomaly_id and out["status"] in ("success", "simulated") and action in ("block_ip", "flush_dns"):
            self.db.update_row("anomalies", int(anomaly_id), {"status": "resolved"})
        return self.db.get_action(aid)

    # 각 조치 구현 -------------------------------------------------
    def _do_connectivity_check(self, params, elevate):
        ctx, pc = self.ctx(), self.cfg().probe
        r = probe.run_probe(ctx.get("gateway"), pc.external_target, pc.dns_test_domains)
        if params.get("target"):
            try:
                r["target"] = probe.ping(system.normalize_ip(params["target"]))
            except ValueError:
                pass
        gw, ext, dns = r.get("gateway") or {}, r.get("external") or {}, r.get("dns") or {}
        steps = []
        steps.append(("공유기(게이트웨이)", gw.get("ok"), _ping_text(gw)))
        steps.append(("외부 인터넷", ext.get("ok"), _ping_text(ext)))
        if r.get("target"):
            steps.append((f"대상 {params['target']}", r["target"].get("ok"), _ping_text(r["target"])))
        steps.append(("DNS 조회", dns.get("tested") and dns.get("failed") == 0,
                      f"{dns.get('tested', 0)}건 중 {dns.get('failed', 0)}건 실패" + (f", 평균 {dns['avg_ms']}ms" if dns.get("avg_ms") else "")))
        if not gw.get("ok") and gw.get("target"):
            verdict = "공유기와 연결되지 않아요. Wi-Fi 연결 또는 랜선을 확인하고, 공유기를 재시작해 보세요."
        elif not ext.get("ok"):
            verdict = "공유기까지는 연결되지만 외부 인터넷 응답이 없어요. 통신사 회선 또는 공유기의 인터넷 연결을 확인해 보세요."
        elif dns.get("failed"):
            verdict = "인터넷은 연결되지만 주소 조회(DNS)가 실패해요. 'DNS 캐시 초기화'를 시도하거나 DNS 서버 설정을 확인해 보세요."
        elif (ext.get("loss_pct") or 0) > 0 or (gw.get("loss_pct") or 0) > 0:
            verdict = "연결은 되지만 일부 데이터 손실이 있어요. 잠시 후 다시 측정해 보세요."
        else:
            verdict = "공유기, 인터넷, 주소 조회 모두 정상이에요."
        ok_all = all(s[1] for s in steps)
        return {"status": "success", "result": {"message": verdict, "steps": [{"label": s[0], "ok": bool(s[1]), "detail": s[2]} for s in steps],
                                               "raw": r, "all_ok": ok_all},
                "verification": {"verified": True, "message": "실측값으로 판정했어요."}}

    def _do_dns_test(self, params, elevate):
        r = probe.dns_test(self.cfg().probe.dns_test_domains)
        msg = "모든 주소 조회가 성공했어요." if r["failed"] == 0 else f"{r['tested']}건 중 {r['failed']}건 실패했어요."
        return {"status": "success", "result": {"message": msg, "dns": r},
                "verification": {"verified": True, "message": msg}}

    def _do_flush_dns(self, params, elevate):
        before = probe.dns_test(self.cfg().probe.dns_test_domains)
        res = system.run_script(self._dns_flush_cmd(), elevate=elevate)
        if res.get("cancelled"):
            return {"status": "cancelled", "result": {"message": res["stderr"]}}
        after = probe.dns_test(self.cfg().probe.dns_test_domains)
        ok = res["returncode"] == 0
        if ok:
            msg = "DNS 캐시를 초기화했어요."
            if after["failed"] < before["failed"]:
                msg += f" 조회 실패가 {before['failed']}건 → {after['failed']}건으로 줄었어요."
            elif after["failed"] == 0:
                msg += " 초기화 후 주소 조회가 모두 정상이에요."
            else:
                msg += f" 하지만 여전히 {after['failed']}건이 실패해요. DNS 서버 자체 문제일 수 있어요."
        else:
            msg = "DNS 캐시 초기화 명령이 실패했어요: " + (res["stderr"] or res["stdout"])[:300]
        return {"status": "success" if ok else "failed",
                "before_state": {"dns_test": before},
                "result": {"message": msg, "output": res, "dns_after": after},
                "verification": {"verified": ok and after["failed"] == 0, "before_failed": before["failed"],
                                 "after_failed": after["failed"], "message": msg}}

    def _do_inspect_ip(self, params, elevate):
        try:
            ip = system.normalize_ip(params.get("ip", ""))
        except ValueError as e:
            raise ActionError(str(e), "invalid_ip")
        h = self.db.ip_history(ip)
        names = self.ctx().get("names") or {}
        s = h["summary"] or {}
        if not s.get("packets"):
            msg = "저장된 기록에 이 장치와의 통신이 없어요 (보존 한도로 지워졌을 수 있어요)."
        else:
            dur = (s["last_ts"] or 0) - (s["first_ts"] or 0)
            msg = f"{terms.describe_ip(ip, self.ctx().get('local_ips'), names)}와 {s['packets']:,}개 패킷, {terms.human_bytes(s['bytes'])}를 주고받았어요 (기간 {dur:.0f}초)."
        return {"status": "success", "result": {"message": msg, "ip": ip, "domain": names.get(ip), "scope": terms.ip_scope(ip), **h}}

    def _do_find_process(self, params, elevate):
        ip = params.get("ip") or None
        port = params.get("port")
        port = int(port) if port not in (None, "") else None
        conns, scope = [], "all"
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            raw, scope = None, "user"
        if raw is not None:
            for c in raw:
                if not c.raddr and not (port and c.laddr and c.laddr.port == port):
                    continue
                conns.append({"pid": c.pid, "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                              "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "", "rip": c.raddr.ip if c.raddr else None,
                              "rport": c.raddr.port if c.raddr else None, "lport": c.laddr.port if c.laddr else None,
                              "status": c.status, "proto": "TCP" if c.type == 1 else "UDP"})
        else:
            conns = _lsof_connections()
        names: dict[int, str] = {}
        for c in conns:
            pid = c.get("pid")
            if pid and pid not in names:
                try:
                    names[pid] = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    names[pid] = c.get("name") or "?"
            c["process"] = names.get(pid, c.get("name") or "(알 수 없음)")
        if ip:
            conns = [c for c in conns if c.get("rip") == ip]
        if port:
            conns = [c for c in conns if port in (c.get("rport"), c.get("lport"))]
        summary: dict[str, dict] = {}
        for c in conns:
            k = f"{c['process']} (PID {c['pid']})"
            s = summary.setdefault(k, {"process": c["process"], "pid": c["pid"], "connections": 0, "remotes": set()})
            s["connections"] += 1
            if c.get("raddr"):
                s["remotes"].add(c["raddr"])
        procs = sorted(({**v, "remotes": sorted(v["remotes"])[:10]} for v in summary.values()), key=lambda x: -x["connections"])
        cond = " / ".join(x for x in (f"IP {ip}" if ip else "", f"포트 {port}" if port else "") if x) or "전체"
        if procs:
            msg = f"{cond} 조건으로 {len(procs)}개 프로그램이 통신 중이에요. 가장 많은 연결: {procs[0]['process']} ({procs[0]['connections']}개)."
        else:
            msg = f"{cond} 조건으로 지금 열려 있는 연결이 없어요. 이미 통신이 끝났거나, 다른 계정(시스템) 프로그램일 수 있어요."
        if scope == "user":
            msg += " (관리자 권한이 없어 내 계정 프로그램만 확인했어요.)"
        return {"status": "success", "result": {"message": msg, "processes": procs[:30], "scope": scope,
                                               "connections": conns[:200]}}

    def _do_block_ip(self, params, elevate):
        ip = params["ip"]
        lines = self.fw.block_script(ip)
        res = system.run_script(lines, elevate=elevate)
        if res.get("cancelled"):
            return {"status": "cancelled", "result": {"message": res["stderr"]}}
        out = res["stdout"] + "\n" + res["stderr"]
        parsed = self.fw.parse_block_output(ip, out)
        ok = parsed.get("applied", False)
        msg = (f"{ip} 를 방화벽({self.fw.label})으로 차단했어요." if ok else
               "방화벽 규칙을 적용하지 못했어요. 출력 내용을 확인해 주세요.")
        return {"status": "success" if ok else "failed",
                "before_state": parsed.get("before_state"),
                "rollback_info": parsed.get("rollback_info") if ok else None,
                "result": {"message": msg, "output": res, "executed_at": time.time()},
                "verification": {"rule_present": ok, "checked_at": time.time(),
                                 "message": "방화벽 목록에서 규칙을 확인했어요." if ok else "방화벽 목록에서 규칙을 찾지 못했어요."}}

    # ───────── 검증 / 롤백 ─────────
    def verify(self, action_id: int) -> dict:
        rec = self.db.get_action(action_id)
        if not rec:
            raise ActionError("조치 기록을 찾을 수 없어요.", "not_found")
        if rec["action"] != "block_ip" or rec["status"] != "success":
            return rec.get("verification") or {"message": "이 조치는 실행 시점에 바로 검증됐어요."}
        ip = rec["params"]["ip"]
        since = rec["created_at"] + 2
        sent = self.db.count_packets_to(ip, since)
        received = self.db.count_packets_from(ip, since)
        capture_on = self.ctx().get("capturing")
        prev = rec.get("verification") or {}
        v = {**prev, "checked_at": time.time(), "packets_sent_after": sent, "packets_seen_from_after": received,
             "capture_running": capture_on}
        if not capture_on:
            v["traffic_verified"] = None
            v["message"] = "캡처가 꺼져 있어서 트래픽 기반 검증을 할 수 없어요. 캡처를 켜고 다시 검증해 주세요."
        elif sent == 0:
            v["traffic_verified"] = True
            v["message"] = (f"차단 후 이 IP로 나가는 데이터가 0개예요. 차단이 동작하고 있어요."
                            + (f" (들어오는 패킷 {received}개가 보이는 건 정상이에요: 캡처는 방화벽보다 먼저 일어나서, 방화벽이 버리는 패킷도 보여요.)" if received else ""))
        else:
            v["traffic_verified"] = False
            v["message"] = f"차단 후에도 이 IP로 나가는 데이터가 {sent}개 보여요. 규칙이 적용되지 않았을 수 있어요."
        self.db.update_row("actions", action_id, {"verification": v})
        return v

    def rollback(self, action_id: int, confirm: bool = False, elevate: bool = False) -> dict:
        rec = self.db.get_action(action_id)
        if not rec:
            raise ActionError("조치 기록을 찾을 수 없어요.", "not_found")
        if rec.get("rolled_back_at"):
            raise ActionError("이미 되돌린 조치예요.", "already")
        info = rec.get("rollback_info")
        if not info:
            raise ActionError("이 조치는 되돌릴 정보가 없어요 (되돌릴 필요가 없는 조치예요).", "not_reversible")
        if not confirm:
            raise ActionError("되돌리기를 확인해 주세요.", "confirmation_required")
        if info.get("simulated") or rec.get("simulated"):
            result = {"removed": True, "message": "시뮬레이션 조치를 되돌렸어요 (실제 시스템 변경 없음)."}
        else:
            ip = info["ip"]
            needs_admin = not system.is_admin()
            if needs_admin and not elevate:
                lines = self.fw.unblock_script(ip, info)
                raise ActionError("차단 해제는 관리자 권한이 필요해요.", "needs_admin",
                                  {"manual_command": self._manual(lines), "can_elevate": system.can_elevate()})
            res = system.run_script(self.fw.unblock_script(ip, info), elevate=elevate and needs_admin)
            if res.get("cancelled"):
                raise ActionError(res["stderr"], "cancelled")
            parsed = self.fw.parse_unblock_output(ip, res["stdout"] + "\n" + res["stderr"])
            result = {**parsed, "output": res,
                      "message": f"{ip} 차단을 해제했어요." if parsed.get("removed") else "차단 해제를 확인하지 못했어요. 출력을 확인해 주세요."}
        self.db.update_row("actions", action_id, {"rolled_back_at": time.time(), "rollback_result": result,
                                                  "status": "rolled_back" if result.get("removed") else rec["status"]})
        if result.get("removed") and rec.get("anomaly_id"):
            # 조치를 되돌렸으면 징후는 다시 '확인 필요' 상태로 (탐지가 계속되면 엔진이 active 로 갱신)
            an = self.db.get_anomaly(int(rec["anomaly_id"]))
            if an and an["status"] == "resolved":
                self.db.update_row("anomalies", an["id"], {"status": "ended"})
        return self.db.get_action(action_id)

    # ───────── 자동 차단 (옵트인) ─────────
    def maybe_auto_block(self, anomaly: dict) -> dict | None:
        cfg = self.cfg()
        if not cfg.auto_block_enabled or anomaly.get("source") != "live":
            return None
        if anomaly["severity"] != "danger" or anomaly["type"] not in self.AUTO_BLOCK_TYPES:
            return None
        if anomaly["type"] == "ip_packet_flood" and (anomaly.get("evidence") or {}).get("bidirectional"):
            return None  # 양방향(정상 대용량 전송 가능성)은 자동 차단 안 함
        ip = anomaly.get("src")
        if not ip or terms.ip_scope(ip) != "public" or not system.is_admin():
            return None  # 사설망 장치·권한 없음 → 자동 차단 안 함 (사용자에게 맡김)
        if any(a["status"] == "success" and (a.get("params") or {}).get("ip") == ip and not a.get("rolled_back_at")
               for a in self.db.list_actions(limit=200) if a["action"] == "block_ip"):
            return None
        try:
            return self.execute("block_ip", {"ip": ip}, anomaly.get("id"), confirm=True, acknowledge_risk=True, trigger="auto")
        except ActionError:
            return None

    def expire_auto_blocks(self):
        now = time.time()
        for a in self.db.list_actions(limit=500):
            if a.get("trigger") == "auto" and a.get("expires_at") and a["expires_at"] <= now and not a.get("rolled_back_at") \
                    and a["status"] == "success":
                try:
                    self.rollback(a["id"], confirm=True)
                except ActionError:
                    pass


def _ping_text(p: dict) -> str:
    if not p or not p.get("target"):
        return (p or {}).get("error") or "측정 대상 없음"
    if not p.get("sent"):
        return f"{p['target']}: 측정 실패 ({p.get('error') or '알 수 없음'})"
    s = f"{p['target']}: {p['received']}/{p['sent']} 응답, 손실 {p['loss_pct']:g}%"
    if p.get("avg_ms") is not None:
        s += f", 평균 {p['avg_ms']:g}ms"
    return s


def _lsof_connections() -> list[dict]:
    res = system.run(["lsof", "-nP", "-i", "-F", "pcnPT"], timeout=15)
    conns, pid, name, proto = [], None, None, None
    for line in res["stdout"].splitlines():
        if not line:
            continue
        k, v = line[0], line[1:]
        if k == "p":
            pid = int(v)
        elif k == "c":
            name = v
        elif k == "P":
            proto = v
        elif k == "n" and "->" in v:
            l, r = v.split("->", 1)
            rip, _, rport = r.rpartition(":")
            lip, _, lport = l.rpartition(":")
            conns.append({"pid": pid, "name": name, "proto": proto, "laddr": l, "raddr": r,
                          "rip": rip.strip("[]"), "rport": int(rport) if rport.isdigit() else None,
                          "lport": int(lport) if lport.isdigit() else None, "status": ""})
    return conns
