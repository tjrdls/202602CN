"""네트워크 인터페이스 정보: 목록, 사람이 읽을 수 있는 이름, 로컬 주소, 게이트웨이, DNS 서버."""
from __future__ import annotations

import platform
import re
import socket
import subprocess
from functools import lru_cache

import psutil

SYSTEM = platform.system()


@lru_cache(maxsize=1)
def _mac_hardware_ports() -> dict[str, str]:
    """macOS: en0 → 'Wi-Fi' 같은 하드웨어 포트 이름."""
    if SYSTEM != "Darwin":
        return {}
    try:
        out = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    names, port = {}, None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            names[line.split(":", 1)[1].strip()] = port
    return names


def _guess_desc(name: str) -> str:
    hw = _mac_hardware_ports().get(name)
    if hw:
        return hw
    low = name.lower()
    if low.startswith("lo"):
        return "루프백 (내 컴퓨터 내부 통신)"
    if low.startswith(("utun", "tun", "wg", "ppp", "ipsec")):
        return "VPN/터널"
    if low.startswith(("awdl", "llw")):
        return "애플 기기 간 무선 직접 연결"
    if low.startswith(("bridge", "vmenet", "vnic", "docker", "veth", "virbr", "vbox")):
        return "가상/브리지 네트워크"
    if low.startswith(("wl", "wi")):
        return "무선 LAN"
    if low.startswith(("en", "eth")):
        return "유선/무선 네트워크"
    return ""


def default_route() -> tuple[str | None, str | None]:
    """(기본 인터페이스, 게이트웨이 IP)."""
    try:
        from scapy.all import conf
        iface, _addr, gw = conf.route.route("0.0.0.0")
        iface_name = getattr(iface, "name", iface)
        return (str(iface_name) if iface_name else None, gw if gw and gw != "0.0.0.0" else None)
    except Exception:
        return (None, None)


def list_interfaces() -> list[dict]:
    """psutil 기반 목록 (캡처는 Scapy 이름을 사용, macOS/Linux 에서는 동일)."""
    default_iface, _ = default_route()
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    can_check_capture = True
    try:
        from scapy.all import get_if_list
        scapy_names = set(get_if_list())
    except Exception:
        scapy_names = set() if SYSTEM == "Windows" else set(addrs)
        can_check_capture = SYSTEM != "Windows"
    result = []
    for name, alist in addrs.items():
        if scapy_names and name not in scapy_names and SYSTEM != "Windows":
            continue
        ipv4 = [a.address for a in alist if a.family == socket.AF_INET]
        ipv6 = [a.address.split("%")[0] for a in alist if a.family == socket.AF_INET6]
        mac = next((a.address for a in alist if a.family == psutil.AF_LINK), None)
        st = stats.get(name)
        capture_iface = capture_name(name)
        result.append({
            "name": name,
            "capture_available": (capture_iface in scapy_names) if can_check_capture else False,
            "description": _guess_desc(name),
            "ipv4": ipv4, "ipv6": ipv6, "mac": mac,
            "is_up": bool(st and st.isup),
            "speed_mbps": st.speed if st else 0,
            "is_default": name == default_iface,
        })
    # 기본 경로 → IPv4 보유 & 활성 → 나머지 순
    result.sort(key=lambda r: (not r["is_default"], not (r["is_up"] and r["ipv4"]), r["name"]))
    return result


def capture_name(name: str) -> str:
    """화면에 보이는 Windows 어댑터 이름을 Scapy/Npcap 장치 이름으로 변환한다."""
    if SYSTEM != "Windows" or name.startswith(r"\Device\NPF_"):
        return name
    if name == "Loopback Pseudo-Interface 1":
        return r"\Device\NPF_Loopback"
    try:
        from scapy.arch.windows import get_windows_if_list
        adapter = next((item for item in get_windows_if_list() if item.get("name") == name), None)
        guid = str((adapter or {}).get("guid", "")).strip("{}")
        return rf"\Device\NPF_{{{guid}}}" if guid else name
    except Exception:
        return name


def local_addresses(iface: str | None = None) -> tuple[set[str], set[str]]:
    """(로컬 IP 집합, 로컬 MAC 집합). iface 가 주어지면 해당 인터페이스 MAC 만 포함."""
    ips, macs = set(), set()
    for name, alist in psutil.net_if_addrs().items():
        for a in alist:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(a.address.split("%")[0])
            elif a.family == psutil.AF_LINK and a.address and (iface is None or name == iface):
                if a.address not in ("00:00:00:00:00:00", ""):
                    macs.add(a.address.lower().replace("-", ":"))
    return ips, macs


def local_networks(iface: str | None = None) -> list[str]:
    """인터페이스의 IPv4/IPv6 서브넷 목록 (예: '172.16.104.0/22')."""
    import ipaddress
    nets = []
    for name, alist in psutil.net_if_addrs().items():
        if iface and name != iface:
            continue
        for a in alist:
            if a.family in (socket.AF_INET, socket.AF_INET6) and a.netmask:
                try:
                    ip = a.address.split("%")[0]
                    mask = a.netmask
                    if a.family == socket.AF_INET6 and "/" not in mask:
                        mask = str(bin(int(ipaddress.IPv6Address(mask))).count("1"))
                    n = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    if not n.is_loopback and n.prefixlen > 0:
                        nets.append(str(n))
                except ValueError:
                    continue
    return nets


def dns_servers() -> list[str]:
    servers: list[str] = []
    try:
        if SYSTEM == "Darwin":
            out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=5).stdout
            servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)
        elif SYSTEM == "Linux":
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                servers = [ln.split()[1] for ln in f if ln.startswith("nameserver") and len(ln.split()) > 1]
        elif SYSTEM == "Windows":
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10).stdout
            servers = re.findall(r"DNS[^\n:]*:\s*([0-9a-fA-F\.:]+)", out)
    except (OSError, subprocess.TimeoutExpired):
        pass
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq
