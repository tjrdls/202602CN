"""NetCare 실행 진입점.

    python run.py              # http://127.0.0.1:8765 에서 실행하고 브라우저를 연다
    python run.py --port 9000 --no-browser
    sudo .venv/bin/python run.py   # (선택) 방화벽 조치·전체 프로세스 확인까지 사용할 때
"""
from __future__ import annotations

import argparse
import logging
import platform
import sys
import threading
import webbrowser

if sys.version_info < (3, 10):
    sys.exit("NetCare 는 Python 3.10 이상이 필요해요.")


def check_capture_permission() -> str | None:
    """캡처 권한을 미리 점검해 안내 문구를 돌려준다 (없으면 None)."""
    system = platform.system()
    try:
        import os
        if system == "Darwin":
            import glob
            bpfs = glob.glob("/dev/bpf*")
            if bpfs and not any(os.access(b, os.R_OK) for b in bpfs):
                return ("macOS 에서 패킷 캡처 권한(/dev/bpf)이 없어요. 'sudo .venv/bin/python run.py' 로 실행하거나 "
                        "Wireshark 의 ChmodBPF 를 설치하세요. (pcap 파일 분석·테스트 데이터는 권한 없이 사용 가능)")
        elif system == "Linux" and os.geteuid() != 0:
            return "Linux 에서는 root 또는 CAP_NET_RAW 권한이 있어야 캡처할 수 있어요. 권한이 없으면 캡처 시작 시 안내가 나와요."
        elif system == "Windows":
            try:
                from scapy.arch.windows import get_windows_if_list  # noqa: F401
            except Exception:
                return "Windows 에서는 Npcap(https://npcap.com) 설치가 필요해요."
    except Exception:
        return None
    return None


def main():
    ap = argparse.ArgumentParser(description="NetCare - 초보자 친화형 네트워크 분석기")
    ap.add_argument("--host", default="127.0.0.1", help="기본값 127.0.0.1 (보안상 외부 접속을 막아요)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true", help="브라우저를 자동으로 열지 않음")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("⚠️  127.0.0.1 이외의 주소에 연결하면 같은 네트워크의 다른 사람이 방화벽 조치 API 에 접근할 수 있어요. "
              "NetCare 는 로컬 전용으로 설계되었기 때문에 Host 검사로 외부 요청을 거부합니다.")

    import uvicorn
    from netcare.api.server import create_app
    from netcare.remediation.system import is_admin

    msg = check_capture_permission()
    url = f"http://127.0.0.1:{args.port}"
    print("\n  NetCare 가 시작됐어요 →", url)
    print("  관리자 권한:", "있음 (방화벽 조치 가능)" if is_admin() else "없음 (방화벽 조치 시 암호 입력 또는 안내)")
    if msg:
        print("  안내:", msg)
    print("  종료하려면 Ctrl+C\n")
    app = create_app()
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
