"""Windows 방화벽(netsh) 조치 검증 스크립트.

관리자 PowerShell 에서 NetCare 폴더로 이동한 뒤:
    .venv\\Scripts\\python.exe scripts\\win_fw_verify.py

- 임시 데이터 폴더를 써서 실제 NetCare 기록(data/)은 건드리지 않습니다.
- 차단 대상 203.0.113.50 은 문서용 예제 주소(RFC 5737)라 실제로 쓰는 곳이 없습니다.
- NetCare 이름이 붙은 규칙만 만들고, 끝나면 되돌리기로 지웁니다(실패해도 마지막에 한 번 더 정리).
- 결과는 docs/win_fw_verify_log.txt 에 저장됩니다.
"""
import errno
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(tempfile.mkdtemp(prefix="nc-fw-"))
os.environ["NETCARE_DATA_DIR"] = str(DATA)
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from netcare.api.server import create_app  # noqa: E402
from netcare.remediation.system import decode_output  # noqa: E402

IP = "203.0.113.50"
RULE = f"NetCare-Block-{IP}"
H = {"X-NetCare": "1"}
log: list[str] = []


def P(*a):
    line = " ".join(str(x) for x in a)
    print(line)
    log.append(line)


def rules() -> str:
    out = decode_output(subprocess.run(f'netsh advfirewall firewall show rule name="{RULE}"',
                                       shell=True, capture_output=True).stdout)
    keep = [l.strip() for l in out.splitlines()
            if l.strip() and not l.startswith("---")]
    return "\n    ".join(keep) if RULE in out else "(없음)"


def try_connect() -> str:
    s = socket.socket()
    s.settimeout(1.5)
    t = time.time()
    try:
        s.connect((IP, 80))
        r = "connected"
    except OSError as e:
        code = getattr(e, "winerror", None) or e.errno
        name = {10013: "WSAEACCES(방화벽이 막음)", 10060: "WSAETIMEDOUT(응답 없음)"}.get(
            code, errno.errorcode.get(e.errno or 0, ""))
        r = f"{type(e).__name__} code={code} {name}"
    finally:
        s.close()
    return f"{r} · {time.time() - t:.2f}초"


def short(o) -> str:
    return json.dumps(o, ensure_ascii=False)[:400]


app = create_app(DATA, start_probe=False)
aid = None
try:
    with TestClient(app) as c:
        st = c.get("/api/status").json()
        P("platform:", st.get("platform"), "· is_admin:", st.get("is_admin"))
        if not st.get("is_admin"):
            P("관리자 권한이 아니에요. PowerShell 을 '관리자 권한으로 실행'한 뒤 다시 실행하세요.")
            sys.exit(1)

        ifs = c.get("/api/interfaces").json().get("interfaces") or []
        P("[0] 인터페이스:", short([(i.get("name"), i.get("ipv4"), i.get("is_default")) for i in ifs])[:300])
        real = [i for i in ifs if any(not a.startswith(("127.", "169.254.")) for a in i.get("ipv4") or [])
                and "loopback" not in str(i.get("name", "")).lower()]
        pick = next((i for i in real if i.get("is_default")), None) or (real[0] if real else None)
        iface = pick["name"] if pick else ""
        cs = c.post("/api/capture/start", json={"iface": iface}, headers=H)
        P("[0] 실시간 캡처 시작 ->", cs.status_code, f"({iface})", "" if cs.status_code < 400 else short(cs.json()))
        time.sleep(1.5)
        P("[0] 차단 전 규칙:", rules())
        for _ in range(2):
            P("[0] 차단 전 접속:", try_connect())
        time.sleep(2)
        seen = c.get("/api/packets", params={"ip": IP, "limit": 50}).json().get("packets") or []
        P("[0] 차단 전 캡처에 잡힌", IP, "패킷:", len(seen), "개 (캡처가 이 IP로 가는 패킷을 볼 수 있는지 대조)")
        r = c.post("/api/actions/execute", json={"action": "block_ip", "params": {"ip": IP}}, headers=H)
        P("[1] 동의 없이 실행 ->", r.status_code, r.json().get("code"))
        r = c.post("/api/actions/execute", json={"action": "block_ip", "params": {"ip": "127.0.0.1"},
                                                  "confirm": True, "acknowledge_risk": True}, headers=H)
        P("[1] 루프백 차단 시도 ->", r.status_code, r.json().get("code"), r.json().get("detail"))

        r = c.post("/api/actions/execute", json={"action": "block_ip", "params": {"ip": IP},
                                                  "confirm": True, "acknowledge_risk": True}, headers=H)
        j = r.json()
        aid = j.get("id") or j.get("action_id")
        P("[2] 동의 후 실행 ->", r.status_code, j.get("status"), "· simulated =", j.get("simulated"))
        if r.status_code >= 400:
            P("    응답:", short(j))
        P("[2] 차단 후 규칙:\n    " + rules())
        P("[3] 차단 후 접속:", try_connect())

        time.sleep(1.5)
        for _ in range(3):
            P("[4] 차단 중 접속:", try_connect())
        time.sleep(2)
        if aid:
            v = c.post(f"/api/actions/{aid}/verify", headers=H)
            P("[4] 효과 확인 ->", v.status_code, short(v.json().get("verification") or v.json()))
            rb = c.post(f"/api/actions/{aid}/rollback", json={"confirm": True}, headers=H)
            P("[5] 되돌리기 ->", rb.status_code, short(rb.json())[:200])
        c.post("/api/capture/stop", headers=H)
        P("[5] 되돌린 후 규칙:", rules())
        P("[6] 되돌린 후 접속:", try_connect())
finally:
    if RULE in rules():
        subprocess.run(f'netsh advfirewall firewall delete rule name="{RULE}"', shell=True)
        P("[정리] 남은 NetCare 규칙을 지웠어요.")
    out = ROOT / "docs" / "win_fw_verify_log.txt"
    out.write_text("\n".join(log), encoding="utf-8")
    print(f"\n로그 저장: {out}")
