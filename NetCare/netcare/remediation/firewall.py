"""운영체제별 방화벽 백엔드.

모든 백엔드는 같은 인터페이스를 가진다.
- block_script(ip) / unblock_script(ip, info): 실행할 명령 줄 목록 (미리보기에도 사용)
- parse_block_output(output): 실행 결과 → 변경 전 상태, 롤백 정보, 적용 여부
- NetCare 가 만든 규칙만 건드린다 (macOS: 전용 anchor, Linux: comment 태그, Windows: 이름 접두사).

macOS 참고: 기본 /etc/pf.conf 에 'anchor "com.apple/*"' 가 있으므로
'com.apple/netcare' 하위 anchor 에 규칙을 넣으면 시스템 설정 파일을 수정하지 않고도 적용된다.
pf 가 꺼져 있었다면 'pfctl -E' 로 참조 토큰을 받아 켜고, 롤백 때 'pfctl -X <토큰>' 으로 반납한다.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
import shutil

from netcare.config import DATA_DIR
from netcare.remediation.system import SYSTEM

ANCHOR = "com.apple/netcare"
TABLE = "netcare_block"


class FirewallBackend:
    name = "none"
    label = "지원하지 않는 운영체제"

    def available(self) -> bool:
        return False

    def block_script(self, ip: str) -> list[str]:
        raise NotImplementedError

    def unblock_script(self, ip: str, info: dict) -> list[str]:
        raise NotImplementedError

    def parse_block_output(self, ip: str, out: str) -> dict:
        return {"applied": False}

    def parse_unblock_output(self, ip: str, out: str) -> dict:
        return {"removed": False}

    @staticmethod
    def _section(out: str, tag: str) -> str:
        m = re.search(rf"##{tag}\n(.*?)(?=\n##|\Z)", out, re.S)
        return m.group(1).strip() if m else ""


class MacPF(FirewallBackend):
    name = "pf"
    label = "macOS 패킷 필터(pf)"

    def __init__(self):
        self.rules_file = DATA_DIR / "pf_netcare.conf"

    def available(self) -> bool:
        return SYSTEM == "Darwin"

    def _ensure_rules_file(self):
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)
        self.rules_file.write_text(
            "# NetCare 가 관리하는 차단 규칙 (anchor com.apple/netcare)\n"
            f"block drop quick from <{TABLE}> to any\n"
            f"block drop quick from any to <{TABLE}>\n", encoding="utf-8")

    def block_script(self, ip: str) -> list[str]:
        self._ensure_rules_file()
        q = shlex.quote(ip)
        allnet = "::/0" if ":" in ip else "0.0.0.0/0"
        return [
            "echo '##BEFORE_STATUS'", "pfctl -s info 2>/dev/null | head -1",
            "echo '##BEFORE_TABLE'", f"pfctl -a {ANCHOR} -t {TABLE} -T show 2>/dev/null",
            "echo '##LOAD'", f"pfctl -a {ANCHOR} -f {shlex.quote(str(self.rules_file))} 2>&1",
            "echo '##ENABLE'", "pfctl -E 2>&1",
            "echo '##ADD'", f"pfctl -a {ANCHOR} -t {TABLE} -T add {q} 2>&1",
            "echo '##KILL'", f"pfctl -k {q} 2>&1; pfctl -k {allnet} -k {q} 2>&1",
            "echo '##AFTER_TABLE'", f"pfctl -a {ANCHOR} -t {TABLE} -T show 2>&1",
        ]

    def parse_block_output(self, ip: str, out: str) -> dict:
        token = re.search(r"Token\s*:\s*(\d+)", self._section(out, "ENABLE"))
        before_status = self._section(out, "BEFORE_STATUS")
        after = self._section(out, "AFTER_TABLE").split()
        return {
            "applied": ip in after,
            "before_state": {"pf_status": before_status or "(확인 불가)",
                             "table_before": self._section(out, "BEFORE_TABLE").split()},
            "rollback_info": {"backend": self.name, "ip": ip, "pf_token": token.group(1) if token else None,
                              "pf_was_enabled": "Enabled" in before_status},
            "after_table": after,
        }

    def unblock_script(self, ip: str, info: dict) -> list[str]:
        q = shlex.quote(ip)
        lines = ["echo '##DELETE'", f"pfctl -a {ANCHOR} -t {TABLE} -T delete {q} 2>&1"]
        tok = info.get("pf_token")
        if tok and str(tok).isdigit():
            lines += ["echo '##RELEASE'", f"pfctl -X {tok} 2>&1"]
        lines += ["echo '##AFTER_TABLE'", f"pfctl -a {ANCHOR} -t {TABLE} -T show 2>&1",
                  "echo '##STATUS'", "pfctl -s info 2>/dev/null | head -1"]
        return lines

    def parse_unblock_output(self, ip: str, out: str) -> dict:
        after = self._section(out, "AFTER_TABLE").split()
        return {"removed": ip not in after, "after_table": after, "pf_status": self._section(out, "STATUS")}


class LinuxIptables(FirewallBackend):
    name = "iptables"
    label = "Linux iptables"

    def available(self) -> bool:
        # 도커 컨테이너에서는 호스트 방화벽을 바꾸지 않는다 (--network host 이면 호스트 규칙이 바뀔 수 있어 막아 둠)
        if os.environ.get("NETCARE_CONTAINER") == "1":
            return False
        return SYSTEM == "Linux" and shutil.which("iptables") is not None

    @staticmethod
    def _bin(ip: str) -> str:
        return "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"

    def block_script(self, ip: str) -> list[str]:
        b, q = self._bin(ip), shlex.quote(ip)
        backup = shlex.quote(str(DATA_DIR / "iptables-backup.rules"))
        return [
            "echo '##BACKUP'", f"{b}-save > {backup} 2>&1 && echo saved:{backup}",
            "echo '##ADD'",
            f"{b} -C INPUT -s {q} -j DROP -m comment --comment NetCare 2>/dev/null || {b} -I INPUT -s {q} -j DROP -m comment --comment NetCare",
            f"{b} -C OUTPUT -d {q} -j DROP -m comment --comment NetCare 2>/dev/null || {b} -I OUTPUT -d {q} -j DROP -m comment --comment NetCare",
            "echo '##AFTER'", f"{b} -S | grep NetCare | grep -F {q}",
        ]

    def parse_block_output(self, ip: str, out: str) -> dict:
        after = self._section(out, "AFTER")
        return {"applied": ip in after, "before_state": {"backup": self._section(out, "BACKUP")},
                "rollback_info": {"backend": self.name, "ip": ip}, "after_rules": after}

    def unblock_script(self, ip: str, info: dict) -> list[str]:
        b, q = self._bin(ip), shlex.quote(ip)
        return ["echo '##DELETE'",
                f"while {b} -D INPUT -s {q} -j DROP -m comment --comment NetCare 2>/dev/null; do :; done",
                f"while {b} -D OUTPUT -d {q} -j DROP -m comment --comment NetCare 2>/dev/null; do :; done",
                "echo '##AFTER'", f"{b} -S | grep NetCare | grep -F {q}; true"]

    def parse_unblock_output(self, ip: str, out: str) -> dict:
        return {"removed": ip not in self._section(out, "AFTER")}


class WindowsNetsh(FirewallBackend):
    name = "netsh"
    label = "Windows Defender 방화벽(netsh)"

    def available(self) -> bool:
        return SYSTEM == "Windows"

    @staticmethod
    def _rule(ip: str) -> str:
        return f"NetCare-Block-{ip.replace(':', '_')}"

    def block_script(self, ip: str) -> list[str]:
        r = self._rule(ip)
        return [f'netsh advfirewall firewall show rule name="{r}"',
                f'netsh advfirewall firewall add rule name="{r}" dir=in action=block remoteip={ip}',
                f'netsh advfirewall firewall add rule name="{r}" dir=out action=block remoteip={ip}',
                f'netsh advfirewall firewall show rule name="{r}"']

    def parse_block_output(self, ip: str, out: str) -> dict:
        return {"applied": out.count(self._rule(ip)) >= 1 and ("Block" in out or "차단" in out),
                "before_state": {"note": "NetCare 전용 이름의 규칙만 추가했어요."},
                "rollback_info": {"backend": self.name, "ip": ip, "rule": self._rule(ip)}}

    def unblock_script(self, ip: str, info: dict) -> list[str]:
        return [f'netsh advfirewall firewall delete rule name="{self._rule(ip)}"']

    def parse_unblock_output(self, ip: str, out: str) -> dict:
        return {"removed": "Deleted" in out or "삭제" in out or "Ok" in out}


def get_backend() -> FirewallBackend:
    for cls in (MacPF, LinuxIptables, WindowsNetsh):
        b = cls()
        if b.available():
            return b
    return FirewallBackend()
