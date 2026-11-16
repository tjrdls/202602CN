"""UI 종단간(E2E) 점검 스크립트.

헤드리스 Chrome 을 DevTools 프로토콜로 조작해 실제 버튼을 누르며 화면 흐름을 확인한다.
- [테스트 데이터] SYN Flood 시나리오 재생 → 문제 해결 화면 → 차단 조치(시뮬레이션) 승인 → 되돌리기
- 안전한 조치 실행, 패킷 상세 드로어, 전문가 모드, 설정 저장 검증, 리포트 그래프
- 페이지에서 발생한 JavaScript 오류/콘솔 오류 수집

사용법 — ⚠️ 테스트 세션·실험 기록을 만들므로 '평소 쓰는 데이터'가 아닌 별도 데이터 폴더로 띄운 서버에서 실행하세요:
    NETCARE_DATA_DIR=/tmp/netcare-e2e .venv/bin/python run.py --no-browser --port 8771 &
    .venv/bin/python scripts/ui_e2e.py --base http://127.0.0.1:8771 [--out 스크린샷폴더] [--chrome 크롬경로]
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websockets

BASE = "http://127.0.0.1:8765"
CHROME_CANDIDATES = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome", "chromium", "chromium-browser",
                     r"C:\Program Files\Google\Chrome\Application\chrome.exe"]


class CDP:
    def __init__(self, ws):
        self.ws, self.i, self.pending, self.errors = ws, 0, {}, []

    async def reader(self):
        async for raw in self.ws:
            m = json.loads(raw)
            if "id" in m and m["id"] in self.pending:
                self.pending.pop(m["id"]).set_result(m)
            elif m.get("method") == "Runtime.exceptionThrown":
                d = m["params"]["exceptionDetails"]
                self.errors.append("JS 예외: " + (d.get("exception", {}).get("description") or d.get("text", "")))
            elif m.get("method") == "Runtime.consoleAPICalled" and m["params"]["type"] == "error":
                self.errors.append("console.error: " + " ".join(str(a.get("value", a.get("description", ""))) for a in m["params"]["args"]))

    async def send(self, method, **params):
        self.i += 1
        fut = asyncio.get_event_loop().create_future()
        self.pending[self.i] = fut
        await self.ws.send(json.dumps({"id": self.i, "method": method, "params": params}))
        r = await asyncio.wait_for(fut, 30)
        if "error" in r:
            raise RuntimeError(r["error"])
        return r.get("result", {})

    async def js(self, expr):
        r = await self.send("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        if r.get("exceptionDetails"):
            raise RuntimeError(r["exceptionDetails"].get("exception", {}).get("description", "eval error"))
        return r.get("result", {}).get("value")

    async def click(self, selector):
        ok = await self.js(f"(() => {{ const el = document.querySelector({json.dumps(selector)}); if (!el) return false; el.click(); return true; }})()")
        if not ok:
            raise AssertionError(f"요소를 찾을 수 없음: {selector}")

    async def wait_for(self, expr, timeout=15):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if await self.js(expr):
                return True
            await asyncio.sleep(0.3)
        raise AssertionError(f"조건 시간 초과: {expr}")

    async def shot(self, path):
        r = await self.send("Page.captureScreenshot", format="png")
        Path(path).write_bytes(base64.b64decode(r["data"]))


async def run(out: Path, chrome: str):
    port = 9333
    prof = tempfile.mkdtemp(prefix="netcare-chrome-")
    proc = subprocess.Popen([chrome, "--headless=new", "--disable-gpu", f"--remote-debugging-port={port}", f"--user-data-dir={prof}",
                             "--window-size=1400,1000", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(("  ✅ " if cond else "  ❌ ") + name + (f" — {detail}" if detail and not cond else ""))

    try:
        for _ in range(50):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                page = next(t for t in tabs if t["type"] == "page")
                break
            except Exception:
                time.sleep(0.2)
        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=50_000_000) as ws:
            c = CDP(ws)
            task = asyncio.create_task(c.reader())
            for d in ("Runtime", "Page"):
                await c.send(f"{d}.enable")
            await c.send("Emulation.setDeviceMetricsOverride", width=1400, height=1000, deviceScaleFactor=1, mobile=False)
            await c.send("Page.navigate", url=f"{BASE}/#home")
            await c.wait_for("!!document.querySelector('#score') && document.querySelector('#score').textContent !== '-'")
            check("홈 화면 로드 및 점수 표시", True)

            # 캡처 중이면 정지
            if await c.js("document.querySelector('#captureBtn').classList.contains('running')"):
                await c.click("#captureBtn")
                await asyncio.sleep(1.5)
            await c.click("#captureBtn")
            await c.wait_for("document.querySelector('#modal').classList.contains('show') && !!document.querySelector('.iface')")
            check("캡처 모달: 인터페이스 목록 표시", await c.js("document.querySelectorAll('.iface').length > 0"))
            await c.click(".source-tabs [data-t=test]")
            await c.wait_for("!!document.querySelector('.scenario')")
            await c.click(".scenario[data-sc=syn_flood]")
            await c.click("#startTest")
            await c.wait_for("document.querySelector('#sourceBadge').textContent.includes('테스트')")
            check("테스트 데이터 배지 표시", True)
            await asyncio.sleep(12)
            await c.shot(out / "e2e_home_test.png")
            check("홈 KPI에 패킷 수 반영", await c.js("parseInt(document.querySelector('#kTotal').textContent.replace(/,/g,'')) > 0"))
            await asyncio.sleep(10)

            await c.send("Page.navigate", url=f"{BASE}/#issues")
            await c.wait_for("!!document.querySelector('#issueDetail .rec')", 20)
            check("문제 해결: 상세와 추천 조치 표시", True)
            # SYN 급증 항목 선택
            await c.js("""(() => { const it = [...document.querySelectorAll('.issue-item')].find(e => e.textContent.includes('새로운 연결 요청')); it && it.click(); })()""")
            await c.wait_for("document.querySelector('.detail-title') && document.querySelector('.detail-title').textContent.includes('새로운 연결 요청')")
            check("판단 근거 게이지 표시", await c.js("!!document.querySelector('.gauge-fill')"))
            await c.shot(out / "e2e_issue.png")

            # 차단 검토 → 모달
            await c.js("""(() => { const b = [...document.querySelectorAll('[data-rec]')].find(e => e.textContent.includes('검토')); b.click(); })()""")
            await c.wait_for("!!document.querySelector('#acRun') || !!document.querySelector('.box-red')")
            check("차단 모달: 동의 전 실행 버튼 비활성", await c.js("document.querySelector('#acRun').disabled === true"))
            check("차단 모달: 부작용 안내 표시", await c.js("document.querySelector('#modalCard').textContent.includes('부작용')"))
            check("차단 모달: 시뮬레이션 안내 표시", await c.js("document.querySelector('#modalCard').textContent.includes('시뮬레이션')"))
            await c.shot(out / "e2e_action_modal.png")
            await c.click("#acChk")
            check("동의 체크 후 실행 버튼 활성", await c.js("document.querySelector('#acRun').disabled === false"))
            await c.click("#acRun")
            await c.wait_for("document.querySelector('#acResult').textContent.length > 0")
            check("조치 결과 표시(시뮬레이션 완료)", await c.js("document.querySelector('#acResult').textContent.includes('완료')"),
                  await c.js("document.querySelector('#acResult').textContent"))
            await c.shot(out / "e2e_action_result.png")
            await c.js("App.closeModal()")
            await c.wait_for("!!document.querySelector('[data-rollback]')", 10)
            check("조치 기록에 되돌리기 버튼 표시", True)
            await c.click("[data-rollback]")
            await c.wait_for("!!document.querySelector('#rbOk')")
            await c.click("#rbOk")
            await c.wait_for("document.querySelector('#rbResult').textContent.length > 0")
            check("되돌리기 완료", await c.js("document.querySelector('#rbResult').textContent.includes('되돌')"),
                  await c.js("document.querySelector('#rbResult').textContent"))
            await c.js("App.closeModal()")
            await asyncio.sleep(1)

            # 안전한 조치: 통신 내역 보기
            await c.js("""(() => { const b = [...document.querySelectorAll('[data-rec]')].find(e => e.textContent.trim() === '실행'); b.click(); })()""")
            await c.wait_for("!!document.querySelector('#acRun')")
            check("안전 조치는 동의 체크 없이 실행 가능", await c.js("document.querySelector('#acRun').disabled === false && !document.querySelector('#acChk')"))
            await c.click("#acRun")
            await c.wait_for("document.querySelector('#acResult').textContent.length > 0", 20)
            check("통신 내역 확인 결과 표시", await c.js("document.querySelector('#acResult').textContent.includes('패킷')"),
                  await c.js("document.querySelector('#acResult').textContent"))
            await c.js("App.closeModal()")

            # 정상 처리 모달
            await c.click("#dismissBtn")
            await c.wait_for("!!document.querySelector('#dmOk')")
            check("정상 처리 모달(화이트리스트 옵션) 표시", await c.js("!!document.querySelector('#wlChk')"))
            await c.js("App.closeModal()")

            # 패킷 화면
            await c.send("Page.navigate", url=f"{BASE}/#packets")
            await c.wait_for("document.querySelectorAll('#pkBody tr').length > 0", 15)
            check("패킷 목록 표시", True)
            await c.click("#pkBody tr")
            await c.wait_for("document.querySelectorAll('#pkDetail .layer, #drawer.show .layer').length > 0", 10)
            check("패킷 상세(넓은 화면: 오른쪽 패널 / 좁은 화면: 드로어): 계층 트리 표시", True)
            await c.shot(out / "e2e_drawer.png")
            await c.js("App.closePacketDetail()")
            await c.click("#pkChips [data-p=DNS]")
            await asyncio.sleep(1.5)
            check("DNS 필터 적용", await c.js("[...document.querySelectorAll('#pkBody tr')].every(tr => tr.textContent.includes('DNS'))"))
            await c.click("#expertBtn")
            await asyncio.sleep(0.5)
            check("전문가 모드: 기술 컬럼 표시", await c.js("document.querySelector('#pkHead').textContent.includes('Protocol')"))
            await c.click("#expertBtn")

            # 설정: 동의 없이 자동 차단 켜기 → 거부되어야 함
            await c.click("#settingsBtn")
            await c.wait_for("!!document.querySelector('[data-det]')")
            check("설정 모달: 탐지 기준 입력란 표시", await c.js("document.querySelectorAll('[data-det]').length >= 10"))
            await c.js("document.querySelector('#ab').checked = true; document.querySelector('#ab').dispatchEvent(new Event('change'))")
            check("자동 차단 켜기 시 경고 표시", await c.js("!document.querySelector('#abBox').classList.contains('hidden')"))
            await c.click("#saveSet")
            await asyncio.sleep(1)
            check("동의 없이 자동 차단 켜기 거부", await c.js("[...document.querySelectorAll('.toast')].some(t => t.textContent.includes('동의'))"))
            await c.js("App.closeModal()")
            st = json.load(urllib.request.urlopen(f"{BASE}/api/settings"))
            check("자동 차단 기본값 유지(꺼짐)", st["auto_block_enabled"] is False)

            # 리포트
            await c.send("Page.navigate", url=f"{BASE}/#report")
            await c.wait_for("!!document.querySelector('#rpKpis .kpi')", 15)
            await c.js("document.querySelector('#rpTest').click()")
            await asyncio.sleep(2.5)
            check("리포트 그래프 렌더링", await c.js("!!document.querySelector('#rpDaily .main-svg') && !!document.querySelector('#rpProto .main-svg')"))
            check("이상 탐지 이력 표 표시", await c.js("document.querySelectorAll('#rpAnom tbody tr').length > 0"))
            await c.shot(out / "e2e_report.png")
            await c.click("#rpCsv")
            await c.wait_for("document.querySelectorAll('#modalCard a[download]').length === 5")
            check("CSV 내보내기 5종 링크", True)
            await c.js("App.closeModal()")

            # 모바일 반응형
            await c.send("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=2, mobile=True)
            await c.send("Page.navigate", url=f"{BASE}/#home")
            await asyncio.sleep(3)
            check("모바일: 하단 탭 바 표시", await c.js("getComputedStyle(document.querySelector('#bottomnav')).display === 'flex'"))
            await c.shot(out / "e2e_mobile.png")

            # ── 실험실 (Simulation Lab) ──
            await c.send("Emulation.setDeviceMetricsOverride", width=1400, height=1000, deviceScaleFactor=1, mobile=False)
            await c.send("Page.navigate", url=f"{BASE}/#lab")
            await c.wait_for("document.querySelectorAll('#labCards .lab-card').length > 0", 15)
            check("실험실: 시나리오 카드 13개(기준선+공격 6+장애 6)", await c.js("document.querySelectorAll('#labCards .lab-card').length === 13"))
            check("실험실: 합성 데이터 안내 배너", await c.js("document.querySelector('.lab-banner').textContent.includes('합성 데이터')"))
            await c.click(".lab-card[data-sc=arp_spoof]")
            await c.wait_for("!!document.querySelector('#lcRun')")
            check("실험실: '의심 수준' 안내 표시(ARP)", await c.js("document.querySelector('#labConfig').textContent.includes('의심')"))
            await c.click("#lcPol [data-v=auto]")
            await c.click("#lcRun")
            await c.wait_for("!document.querySelector('#labResult').classList.contains('hidden') && document.querySelector('#labResult').textContent.includes('결과')", 40)
            check("실험 결과: 탐지 판정 표시", await c.js("document.querySelector('#labResult').textContent.includes('탐지됨')"))
            check("실험 결과: Precision/Recall/F1/FPR 표시", await c.js("['Precision','Recall','F1-score','False Positive Rate'].every(k => document.querySelector('#labResult').textContent.includes(k))"))
            check("실험 결과: 조치 전후 비교 표시", await c.js("!!document.querySelector('#labResult .ba')"))
            check("실험 결과: 1초 단위 타임라인", await c.js("document.querySelectorAll('#labResult .tl span').length > 20"))
            check("실험 결과: 그래프 렌더링", await c.js("!!document.querySelector('#labResChart .main-svg')"))
            await c.send("Emulation.setDeviceMetricsOverride", width=1400, height=2600, deviceScaleFactor=1, mobile=False)
            await c.js("document.querySelector('#labResult').scrollIntoView()")
            await asyncio.sleep(1)
            await c.shot(out / "e2e_lab_result.png")
            await c.send("Emulation.setDeviceMetricsOverride", width=1400, height=1000, deviceScaleFactor=1, mobile=False)
            await c.click("#lrPk")
            await c.wait_for("document.querySelectorAll('#modalCard [data-lp]').length > 0", 10)
            await c.click("#modalCard [data-lp]")
            await c.wait_for("document.querySelector('#drawer').classList.contains('show') && document.querySelectorAll('#drawer .layer').length > 0", 10)
            check("가상 패킷도 같은 헤더 분석(드로어)", await c.js("document.querySelector('#drawer').textContent.includes('시뮬레이션')"))
            await c.js("App.closeDrawer()")
            await c.click("#labSeg [data-p=hist]")
            await c.wait_for("document.querySelectorAll('#labHistPane [data-ex]').length > 0", 10)
            check("실험 이력 표 표시", True)
            await c.click("#labSeg [data-p=bench]")
            await c.wait_for("!!document.querySelector('#bnRun')", 10)
            check("벤치마크 화면 표시", True)
            await c.shot(out / "e2e_lab_bench.png")
            main_an = json.load(urllib.request.urlopen(f"{BASE}/api/anomalies"))["anomalies"]
            check("실험실 결과가 실제 데이터(문제 해결 목록)에 섞이지 않음", all(a["source"] != "sim" for a in main_an))

            # ── 디자인 시스템: 다크 모드·UI 키트·단축키 ──
            await c.send("Page.navigate", url=f"{BASE}/#home")
            await c.wait_for("!!document.querySelector('#score') && document.querySelector('#score').textContent !== '-'")
            bg_light = await c.js("getComputedStyle(document.body).backgroundColor")
            await c.click("#themeBtn")
            await asyncio.sleep(0.6)
            bg_dark = await c.js("getComputedStyle(document.body).backgroundColor")
            check("다크 모드: 테마 버튼으로 전환(data-theme=dark, 배경색 변화)", await c.js("document.documentElement.dataset.theme === 'dark'") and bg_light != bg_dark)
            check("다크 모드: 설정이 저장됨(localStorage)", await c.js("localStorage.getItem('nc.theme') === 'dark'"))
            await c.send("Page.navigate", url=f"{BASE}/#home")
            await asyncio.sleep(1.5)
            check("다크 모드: 새로고침 후 유지", await c.js("document.documentElement.dataset.theme === 'dark'"))
            check("다크 모드: 그래프 글자색이 토큰을 따름", await c.js("(() => { const t = document.querySelector('#chTraffic .xtick text, #chProto text'); return !t || t.style.fill !== 'rgb(107, 117, 132)'; })()"))
            await c.shot(out / "e2e_home_dark.png")
            await c.js("document.body.focus()")
            await c.send("Input.dispatchKeyEvent", type="keyDown", key="d", code="KeyD", text="d")
            await c.send("Input.dispatchKeyEvent", type="keyUp", key="d", code="KeyD")
            await asyncio.sleep(0.5)
            check("단축키 d: 라이트 모드로 복귀", await c.js("document.documentElement.dataset.theme === 'light'"))
            await c.send("Input.dispatchKeyEvent", type="keyDown", key="2", code="Digit2", text="2")
            await c.send("Input.dispatchKeyEvent", type="keyUp", key="2", code="Digit2")
            await asyncio.sleep(0.8)
            check("단축키 2: 패킷 분석 화면으로 이동", await c.js("!document.querySelector('#view-packets').classList.contains('hidden')"))
            await c.click("#settingsBtn")
            await c.wait_for("!!document.querySelector('#thSeg')")
            check("설정: 테마 선택(시스템/라이트/다크) 표시", await c.js("document.querySelectorAll('#thSeg button').length === 3"))
            await c.js("App.closeModal()")
            await c.send("Page.navigate", url=f"{BASE}/static/ui-kit.html")
            await asyncio.sleep(1.5)
            check("UI 키트 페이지 렌더링(버튼·배지·표·빈 상태)", await c.js("['.btn-primary','.sev-badge','table.pk','.empty','.skeleton','.banner.sim'].every(s => !!document.querySelector(s))"))

            # ── 3단계: 화면 리디자인 ──
            await c.send("Page.navigate", url=f"{BASE}/#home")
            await c.wait_for("!!document.querySelector('#score') && document.querySelector('#score').textContent !== '-'")
            await asyncio.sleep(1.2)
            check("홈: 최근 탐지 이벤트 카드", await c.js("document.querySelectorAll('#recentAnoms li[data-anom]').length > 0"))
            check("홈: 주요 통신 장치 목록(IP 링크)", await c.js("document.querySelectorAll('#peerList .ip-link').length > 0"))
            await c.click("#peerList .ip-link")
            await c.wait_for("document.querySelector('#modal').classList.contains('show') && document.querySelector('#modalCard').textContent.includes('보낸 데이터')", 10)
            check("IP 상세 팝업: 보낸/받은 데이터·상대·포트", await c.js("['보낸 데이터','받은 데이터','많이 통신한 상대'].every(k => document.querySelector('#modalCard').textContent.includes(k))"))
            await c.shot(out / "e2e_ip_detail.png")
            await c.click("#ipPk")
            await c.wait_for("!document.querySelector('#view-packets').classList.contains('hidden') && document.querySelectorAll('#pkBody tr').length > 0", 10)
            check("IP 팝업 → 패킷 화면 IP 필터 적용", await c.js("document.querySelector('#pkIp').value.length > 0 && document.querySelector('#pkInfo').textContent.includes('IP')"))
            await c.click("#pkClear")
            await asyncio.sleep(1.2)
            await c.click("#pkHead th[data-sort=length]")
            await c.wait_for("!document.querySelector('#pkPager').classList.contains('hidden')", 10)
            check("패킷: 열 정렬 → 페이지 모드(전체 개수·페이지 표시)", await c.js("document.querySelector('#pkInfo').textContent.includes('전체') && document.querySelector('#pkHead th.sortable.desc, #pkHead th.sortable.asc') !== null"))
            lens = await c.js("[...document.querySelectorAll('#pkBody tr td.num')].slice(0,5).map(td => parseFloat(td.textContent))")
            check("패킷: 크기 내림차순 정렬 반영", lens == sorted(lens, reverse=True), str(lens))
            await c.js("document.querySelector('#pkPort').value='443'; document.querySelector('#pkPort').dispatchEvent(new Event('input'))")
            await asyncio.sleep(1.2)
            check("패킷: 포트 필터(443)", await c.js("[...document.querySelectorAll('#pkBody tr td.mono')].some(td => td.textContent.includes('443')) && document.querySelector('#pkInfo').textContent.includes('포트 443')"))
            await c.click("#pkLiveBack")
            await asyncio.sleep(1)
            check("패킷: 실시간 보기로 복귀", await c.js("document.querySelector('#pkPager').classList.contains('hidden')"))
            await c.click("#pkBody tr[data-id]")
            await c.wait_for("!document.querySelector('#pkDetail').classList.contains('hidden') && document.querySelectorAll('#pkDetail .layer').length > 0", 10)
            check("패킷: 넓은 화면에서 오른쪽 상세 패널", await c.js("document.querySelector('#pkLayout').classList.contains('with-detail') && !document.querySelector('#drawer').classList.contains('show')"))
            await c.shot(out / "e2e_packets_split.png")
            await c.js("App.closePacketDetail()")
            # 전역 검색
            await c.send("Input.dispatchKeyEvent", type="keyDown", key="k", code="KeyK", text="k", modifiers=2)
            await c.send("Input.dispatchKeyEvent", type="keyUp", key="k", code="KeyK", modifiers=2)
            await c.wait_for("!!document.querySelector('#gsInput')", 5)
            await c.js("document.querySelector('#gsInput').value='203'; document.querySelector('#gsInput').dispatchEvent(new Event('input'))")
            await c.wait_for("document.querySelectorAll('#gsResults .sr-item').length > 0", 10)
            check("전역 검색(Ctrl+K): IP·이상 징후 결과", await c.js("document.querySelector('#gsResults').textContent.includes('장치(IP)') && document.querySelector('#gsResults').textContent.includes('이상 징후')"))
            await c.shot(out / "e2e_search.png")
            await c.click("#gsResults [data-anom]")
            await c.wait_for("!document.querySelector('#view-issues').classList.contains('hidden') && !!document.querySelector('#issueDetail .timeline')", 10)
            check("문제 해결: ①~⑦ 단계 구조·타임라인·정상 비교", await c.js("['① 언제','③ 왜','④ 정상 상황','⑤ 예상','⑥ 이렇게','⑦ 진행 타임라인'].every(k => document.querySelector('#issueDetail').textContent.includes(k)) && document.querySelectorAll('#issueDetail .timeline li').length >= 2 && !!document.querySelector('#issueDetail .compare')"))
            await c.shot(out / "e2e_issue_v2.png")
            # 리포트 확장
            await c.send("Page.navigate", url=f"{BASE}/#report")
            await c.wait_for("!!document.querySelector('#rpKpis .kpi')", 10)
            await c.js("document.querySelector('#rpTest').checked = true; document.querySelector('#rpTest').dispatchEvent(new Event('change'))")
            await c.wait_for("!!document.querySelector('#rpSev .main-svg') && document.querySelectorAll('#rpActions tbody tr').length > 0 && document.querySelector('#rpLab').textContent.length > 20", 15)
            check("리포트: KPI 6개·위험 수준별 그래프·대응 결과 표·실험실 요약", await c.js("document.querySelectorAll('#rpKpis .kpi').length === 6 && document.querySelector('#rpLab').textContent.includes('합성')"))
            await c.click("#rpSeg [data-d=custom]")
            await asyncio.sleep(0.5)
            check("리포트: 기간 직접 선택 입력 표시", await c.js("!document.querySelector('#rpRange').classList.contains('hidden') && document.querySelector('#rpStart').value.length === 10"))
            await c.shot(out / "e2e_report_v2.png")
            # 실험실 보강: 카드 메타·예상 결과·실시간 일시정지·요약 문장
            await c.send("Page.navigate", url=f"{BASE}/#lab")
            await c.wait_for("document.querySelectorAll('#labCards .lab-card').length > 0", 15)
            check("실험실: 카드에 목적·난이도·지난 결과", await c.js("document.querySelectorAll('#labCards .lc-meta').length >= 13 && document.querySelector('#labCards').textContent.includes('지난')"))
            await c.click(".lab-card[data-sc=syn_flood]")
            await c.wait_for("!!document.querySelector('#lcRun')")
            check("실험실: 실행 전 예상 결과 안내", await c.js("document.querySelector('#labConfig').textContent.includes('실행하면 이렇게 돼요')"))
            await c.js("document.querySelector('#lcDur').value=8; document.querySelector('#lcA0').value=2; document.querySelector('#lcA1').value=6")
            await c.click("#lcSpeed [data-v=realtime]")
            await c.click("#lcRun")
            await c.wait_for("!!document.querySelector('#labPause')", 15)
            await c.click("#labPause")
            await asyncio.sleep(1.5)
            st = json.load(urllib.request.urlopen(f"{BASE}/api/lab/status"))
            check("실험실: 실시간 실험 일시정지", bool(st.get("experiment", {}).get("paused")))
            sec0 = st["experiment"]["sec"]
            await asyncio.sleep(2.2)
            st2 = json.load(urllib.request.urlopen(f"{BASE}/api/lab/status"))
            check("실험실: 일시정지 중 진행 멈춤", st2.get("experiment", {}).get("sec") == sec0)
            await c.click("#labPause")
            await c.wait_for("!document.querySelector('#labResult').classList.contains('hidden') && document.querySelector('#labResult').textContent.includes('결과')", 40)
            check("실험 결과: 자동 요약 문장", await c.js("!!document.querySelector('#labResult .summary-box') && document.querySelector('#labResult .summary-box').textContent.includes('합성 데이터')"))
            # 4단계: 규칙 카탈로그
            await c.send("Page.navigate", url=f"{BASE}/#issues")
            await c.wait_for("!!document.querySelector('#rulesBtn')", 10)
            await c.click("#rulesBtn")
            await c.wait_for("document.querySelectorAll('#modalCard [data-rule]').length >= 22", 10)
            await c.click("#modalCard [data-rule=syn_surge]")
            await asyncio.sleep(0.4)
            check("규칙 카탈로그: 22종 목록 + 조건·임계값·오탐·한계 상세", await c.js("['탐지 조건','오탐 가능성','한계','syn_threshold'].every(k => document.querySelector('#ruleDetail').textContent.includes(k))"))
            await c.shot(out / "e2e_rules.png")
            await c.js("App.closeModal()")
            await c.wait_for("!!document.querySelector('#issueDetail #ruleBtn')", 10)
            await c.click("#issueDetail #ruleBtn")
            await c.wait_for("!!document.querySelector('#ruleDetail h3')", 10)
            check("문제 해결 상세 → 해당 규칙 설명 열기", await c.js("document.querySelector('#modalCard [data-rule].on') !== null"))
            await c.js("App.closeModal()")
            rules_api = json.load(urllib.request.urlopen(f"{BASE}/api/rules"))["rules"]
            check("API /api/rules: 규칙마다 조건·임계값·근거·위험 수준·오탐·환경·한계", all(r.get(k) for r in rules_api for k in ("condition", "evidence", "severity", "false_positives", "environments", "limits")))

            # 모바일에서 새 요소 확인
            await c.send("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=2, mobile=True)
            await c.send("Page.navigate", url=f"{BASE}/#issues")
            await asyncio.sleep(2.5)
            check("모바일: 문제 해결 상세 1열 배치", await c.js("getComputedStyle(document.querySelector('.issues-layout')).gridTemplateColumns.split(' ').length === 1"))
            await c.shot(out / "e2e_mobile_issue.png")
            await c.send("Emulation.setDeviceMetricsOverride", width=1400, height=1000, deviceScaleFactor=1, mobile=False)

            check("JavaScript 오류 없음", not c.errors, "; ".join(c.errors[:5]))
            task.cancel()
    finally:
        proc.terminate()
        shutil.rmtree(prof, ignore_errors=True)
    passed = sum(1 for r in results if r[1])
    print(f"\n결과: {passed}/{len(results)} 통과 · 스크린샷: {out}")
    return passed == len(results)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "docs" / "screenshots"))
    ap.add_argument("--chrome", default=None)
    ap.add_argument("--base", required=True, help="별도 데이터 폴더로 띄운 테스트 서버 주소 (예: http://127.0.0.1:8771)")
    a = ap.parse_args()
    global BASE
    BASE = a.base.rstrip("/")
    chrome = a.chrome or next((c for c in CHROME_CANDIDATES if shutil.which(c) or Path(c).exists()), None)
    if not chrome:
        sys.exit("Chrome/Chromium 을 찾을 수 없어요. --chrome 으로 경로를 지정하세요.")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ok = asyncio.run(run(out, chrome))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
