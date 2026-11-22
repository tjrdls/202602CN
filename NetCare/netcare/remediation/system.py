"""운영체제 관련 공통 기능: 관리자 권한 확인, 명령 실행, 보호 대상 IP 판별."""
from __future__ import annotations

import ipaddress
import locale
import os
import platform
import shlex
import subprocess
import time

SYSTEM = platform.system()


def is_admin() -> bool:
    try:
        if SYSTEM == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return False


def can_elevate() -> bool:
    """관리자 권한이 없을 때 OS 암호 창으로 권한 상승을 요청할 수 있는가 (macOS 전용)."""
    return SYSTEM == "Darwin" and not is_admin()


def decode_output(b: bytes | None) -> str:
    """명령 출력 바이트를 문자열로. Windows 는 콘솔 설정에 따라 UTF-8 또는 CP949 로 나오므로 차례로 시도한다."""
    if not b:
        return ""
    for enc in ("utf-8", locale.getpreferredencoding(False), "cp949"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "replace")


def run(cmd: list[str], timeout: float = 20) -> dict:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return {"cmd": " ".join(shlex.quote(c) for c in cmd), "returncode": p.returncode,
                "stdout": decode_output(p.stdout)[-4000:], "stderr": decode_output(p.stderr)[-2000:],
                "elapsed": round(time.time() - t0, 2)}
    except FileNotFoundError:
        return {"cmd": " ".join(cmd), "returncode": 127, "stdout": "", "stderr": f"명령을 찾을 수 없어요: {cmd[0]}", "elapsed": 0}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "returncode": 124, "stdout": "", "stderr": "시간 초과", "elapsed": timeout}


def run_script(lines: list[str], elevate: bool, timeout: float = 60) -> dict:
    """여러 줄 쉘 스크립트 실행. elevate=True 면 macOS 관리자 암호 창을 띄운다.

    lines 의 각 줄은 이 모듈 밖에서 검증된 값(IP 등)만 shlex.quote 로 넣어 만든다.
    """
    script = "\n".join(lines)
    if SYSTEM == "Windows":
        # Windows 는 cmd 를 줄 단위로 실행
        outs = [run(["cmd", "/c", ln], timeout) for ln in lines if not ln.startswith("echo ##")]
        return {"cmd": script, "returncode": max((o["returncode"] for o in outs), default=0),
                "stdout": "\n".join(o["stdout"] for o in outs), "stderr": "\n".join(o["stderr"] for o in outs)}
    if elevate:
        if SYSTEM != "Darwin":
            return {"cmd": script, "returncode": 1, "stdout": "", "stderr": "이 운영체제에서는 암호 창 권한 상승을 지원하지 않아요."}
        apple = 'do shell script ' + _applescript_quote(script) + ' with administrator privileges'
        res = run(["osascript", "-e", apple], timeout=timeout + 120)  # 사용자가 암호를 입력할 시간
        if res["returncode"] != 0 and "-128" in res["stderr"]:
            res["stderr"] = "사용자가 관리자 암호 입력을 취소했어요."
            res["cancelled"] = True
        res["cmd"] = script
        return res
    res = run(["/bin/sh", "-c", script], timeout)
    res["cmd"] = script
    return res


def _applescript_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        raise ValueError(f"'{ip}' 은(는) 올바른 IP 주소가 아니에요.")


def protection_reason(ip: str, ctx: dict) -> str | None:
    """차단하면 안 되는 IP 이면 그 이유를, 아니면 None."""
    a = ipaddress.ip_address(ip)
    if ip in (ctx.get("local_ips") or set()):
        return "내 컴퓨터의 주소예요. 차단하면 이 컴퓨터의 네트워크가 동작하지 않아요."
    if ip == ctx.get("gateway"):
        return "공유기(게이트웨이) 주소예요. 차단하면 인터넷 전체가 끊겨요."
    if ip in (ctx.get("dns_servers") or []):
        return "사용 중인 DNS 서버예요. 차단하면 웹사이트 주소를 찾을 수 없게 돼요."
    if a.is_loopback:
        return "내 컴퓨터 내부 통신 주소(루프백)예요."
    if a.is_multicast:
        return "멀티캐스트 주소예요. 여러 장치에 동시에 전달되는 특수 주소라 차단 대상이 아니에요."
    if a.is_unspecified or (a.version == 4 and (ip == "255.255.255.255" or ip.endswith(".255"))):
        return "브로드캐스트/특수 주소예요."
    if a.is_link_local:
        return "링크 로컬 주소예요. 같은 네트워크 자동 설정에 쓰이므로 차단하지 않아요."
    for w in ctx.get("whitelist") or []:
        try:
            if a in ipaddress.ip_network(w, strict=False):
                return f"화이트리스트({w})에 등록된 주소예요."
        except ValueError:
            continue
    return None
