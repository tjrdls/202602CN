/* NetCare 웹 UI 진입점 — 빌드 도구 없이 ES 모듈로 동작한다.
 * 모든 화면 값은 백엔드 API(실제 캡처·측정 데이터)에서 가져온다. */
import { S, $, $$, api, esc, num, toast, hooks } from "./core.js";
import { applyTheme, toggleTheme, onThemeChange, resolvedTheme } from "./theme.js";
import { restyleAll } from "./charts.js";
import { closeModal, closeDrawer, isModalOpen, isDrawerOpen } from "./ui.js";
import { loadDashboard, drawTraffic, bindHome } from "./views/home.js";
import { renderPkHead, renderPackets, loadPackets, openPacket, renderPacketDrawer, bindPackets, closePacketDetail } from "./views/packets.js";
import { openSearch } from "./search.js";
import { openIpDetail } from "./ipdetail.js";
import { openRules, bindRules } from "./rules.js";
import { loadIssues, selectIssue, renderIssueDetail, bindIssues } from "./views/issues.js";
import { loadReport, bindReport } from "./views/report.js";
import { loadLab, labTick, bindLab } from "./views/lab.js";
import { onCaptureBtn, uploadPcap } from "./capture.js";
import { openSettings } from "./settings.js";

const VIEWS = ["home", "packets", "issues", "report", "lab"];

/* ── 화면 전환 ── */
function go(view) {
  const [v, arg] = String(view).split("/");
  view = VIEWS.includes(v) ? v : "home";
  S.view = view;
  if (location.hash.split("/")[0] !== "#" + view) history.replaceState(null, "", "#" + view);
  if (arg && view === "issues") setTimeout(() => selectIssue(+arg), 0);
  if (arg && view === "packets") setTimeout(() => openPacket(+arg), 0);
  if (view !== "packets" && S.lastPacket) closePacketDetail();
  $$(".view").forEach((el) => el.classList.toggle("hidden", el.id !== `view-${view}`));
  $$("[data-view]").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  window.scrollTo({ top: 0 });
  if (view === "packets") { renderPkHead(); loadPackets(true); }
  if (view === "issues") loadIssues();
  if (view === "report") loadReport();
  if (view === "home") loadDashboard();
  if (view === "lab") loadLab();
  setTimeout(() => window.dispatchEvent(new Event("resize")), 50);
}

/* ── 상태 / 배너 / 캡처 버튼 ── */
function applyStatus(st) {
  S.status = st;
  const running = ["capturing", "importing", "testing"].includes(st.state);
  const btn = $("#captureBtn");
  btn.classList.toggle("running", running);
  $("#captureBtnText").textContent = running ? (st.state === "capturing" ? "캡처 중지" : "분석 중지") : "캡처 시작";
  const sess = st.session;
  const badge = $("#sourceBadge");
  if (sess) {
    badge.classList.remove("hidden");
    if (sess.source === "test") { badge.className = "status-pill s-test"; badge.textContent = "테스트 데이터"; }
    else if (sess.source === "pcap") { badge.className = "status-pill s-pcap"; badge.textContent = running ? "파일 분석 중" : "파일 분석 결과"; }
    else { badge.className = "status-pill " + (running ? "s-good" : "s-info"); badge.textContent = running ? `실시간 캡처 · ${sess.iface}` : "캡처 멈춤"; }
  } else badge.classList.add("hidden");

  const b = [];
  if (st.error) b.push(["error", st.error.message, st.error.help]);
  if (sess && sess.source === "test") b.push(["sim", "지금 보이는 데이터는 테스트용 가상 데이터예요", `‘${sess.title.replace("[테스트 데이터] ", "")}’ 시나리오를 재생하고 있어요. 실제 네트워크 상황이 아니며, 방화벽 같은 조치도 시뮬레이션으로만 실행돼요.`]);
  if (sess && sess.source === "pcap") b.push(["info", "저장된 pcap 파일을 분석한 결과예요", `${sess.title} · 지금 진행 중인 통신이 아니에요.`]);
  if (st.dropped > 0) b.push(["warn", `처리 속도가 따라가지 못해 패킷 ${num(st.dropped)}개를 놓쳤어요`, "통계가 실제보다 적게 나올 수 있어요. 캡처 필터로 범위를 좁히면 줄일 수 있어요."]);
  if (!sess && !st.error) b.push(["info", "아직 캡처를 시작하지 않았어요", "오른쪽 위 ‘캡처 시작’을 눌러 내 네트워크를 살펴보세요. 권한이 없어도 pcap 파일 분석이나 테스트 데이터로 체험할 수 있어요."]);
  $("#banners").innerHTML = b.map(([k, t, d]) => `<div class="banner ${k}"><div class="banner-body"><b>${esc(t)}</b>${d ? esc(d) : ""}</div></div>`).join("");
}

/* ── 전문가 모드 ── */
function setExpert(v) {
  S.expert = v; localStorage.setItem("nc.expert", v ? "1" : "0");
  $("#expertBtn").classList.toggle("on", v);
  renderPkHead(); renderPackets(); renderPacketDrawer(); renderIssueDetail();
}

/* ── 테마 ── */
function updateThemeBtn() {
  const dark = resolvedTheme() === "dark";
  $("#themeBtn").title = dark ? "라이트 모드로" : "다크 모드로";
  $("#themeIconSun").classList.toggle("hidden", !dark);
  $("#themeIconMoon").classList.toggle("hidden", dark);
}

/* ── 폴링 ── */
let offline = false;
function showOffline() {
  if (offline) return; offline = true;
  $("#banners").innerHTML = `<div class="banner error"><div class="banner-body"><b>NetCare 서버와 연결이 끊겼어요</b>터미널에서 프로그램이 실행 중인지 확인해 주세요. 다시 연결되면 자동으로 이어져요.</div></div>`;
}
let busy = false, n = 0;
async function tick() {
  if (busy) return; busy = true;
  try {
    if (S.view === "lab") await labTick();
    if (S.view === "home") await loadDashboard();
    else { const st = await api("/api/status"); applyStatus(st); }
    offline = false;
    if (S.view === "packets" && !S.pk.paused) await loadPackets();
    if (S.view === "issues" && n % 3 === 0) await loadIssues();
    if (S.view !== "home" && n % 3 === 0) {
      const d = await api("/api/anomalies?status=active&limit=200&scope=session");
      const b = $("#issueBadge"); b.textContent = d.anomalies.length; b.classList.toggle("hidden", !d.anomalies.length);
    }
  } catch (e) { if (e.offline) showOffline(); }
  finally { busy = false; n++; }
}

/* ── 키보드 단축키 ── */
function onKey(e) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openSearch(); return; }
  if (e.key === "Escape") { closeModal(); closeDrawer(); return; }
  const tag = (e.target && e.target.tagName) || "";
  if (["INPUT", "TEXTAREA", "SELECT"].includes(tag) || e.target.isContentEditable || e.metaKey || e.ctrlKey || e.altKey) return;
  if (isModalOpen()) return;
  if (e.key >= "1" && e.key <= "5") { go(VIEWS[+e.key - 1]); e.preventDefault(); }
  else if (e.key === "/") { e.preventDefault(); if (S.view === "packets") $("#pkSearch").focus(); else openSearch(); }
  else if (e.key === "e") setExpert(!S.expert);
  else if (e.key === "d") { toggleTheme(); }
  else if (e.key === "?") showShortcuts();
}
function showShortcuts() {
  import("./ui.js").then(({ modal }) => modal(`<h3>키보드 단축키</h3>
    <table class="mini-table"><tr><td><span class="kbd">1</span>~<span class="kbd">5</span></td><td>홈 · 패킷 분석 · 문제 해결 · 리포트 · 실험실</td></tr>
    <tr><td><span class="kbd">⌘K</span> / <span class="kbd">Ctrl+K</span></td><td>전역 검색 (IP·도메인·포트·이상 징후)</td></tr>
    <tr><td><span class="kbd">/</span></td><td>패킷 화면에서는 패킷 검색, 그 외에는 전역 검색</td></tr><tr><td><span class="kbd">e</span></td><td>전문가 모드 전환</td></tr>
    <tr><td><span class="kbd">d</span></td><td>다크·라이트 전환</td></tr><tr><td><span class="kbd">Esc</span></td><td>창 닫기</td></tr><tr><td><span class="kbd">?</span></td><td>이 도움말</td></tr></table>
    <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button></div>`));
}

/* ── 초기화 ── */
async function init() {
  hooks.go = go; hooks.tick = tick; hooks.applyStatus = applyStatus; hooks.showOffline = showOffline;
  applyTheme(); updateThemeBtn();
  onThemeChange(() => { updateThemeBtn(); restyleAll(); if (S.view === "home" && S.dash) drawTraffic(S.dash.stats); });
  $$("[data-view]").forEach((b) => b.onclick = () => go(b.dataset.view));
  $("#captureBtn").onclick = onCaptureBtn;
  $("#settingsBtn").onclick = openSettings;
  $("#themeBtn").onclick = () => toggleTheme();
  $("#searchBtn").onclick = () => openSearch();
  document.addEventListener("click", (e) => { const el = e.target.closest(".ip-link[data-ip]"); if (el) { e.preventDefault(); openIpDetail(el.dataset.ip); } });
  $("#expertBtn").onclick = () => { setExpert(!S.expert); toast(S.expert ? "전문가 모드: 원본 헤더 이름과 값을 보여줘요" : "쉬운 모드로 돌아왔어요"); };
  bindHome(); bindPackets(); bindIssues(); bindReport(); bindLab(); bindRules();
  $("#rulesBtn").onclick = () => openRules();
  $("#scrim").onclick = closeDrawer;
  $("#modal").onclick = (e) => { if (e.target.id === "modal") closeModal(); };
  document.addEventListener("keydown", onKey);
  $("#pcapInput").onchange = (e) => { const f = e.target.files[0]; if (f) uploadPcap(f); e.target.value = ""; };
  try {
    S.catalog = await api("/api/actions/catalog");
    const st = await api("/api/status");
    if (localStorage.getItem("nc.expert") === null && st.config.expert_mode_default) S.expert = true;
  } catch (e) { showOffline(); }
  setExpert(S.expert);
  go((location.hash || "#home").slice(1));
  window.addEventListener("hashchange", () => { const v = location.hash.slice(1); if (v !== S.view) go(v); });
  setInterval(tick, 1000);
}
window.App = { go, closeDrawer, closeModal, closePacketDetail, selectIssue, openPacket, openIpDetail, openSearch, openRules, S };
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
