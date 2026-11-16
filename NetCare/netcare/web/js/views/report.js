/* 리포트 */
import { S, $, $$, api, esc, num, bytes, dt, toast, hooks, pct, STATUS_KO, ACT_STATUS } from "../core.js";
import { plot, emptyChart, ensureChart } from "../charts.js";
import { palette } from "../theme.js";
import { sevPill, srcPill, modal, emptyHtml } from "../ui.js";
import { selectIssue } from "./issues.js";

Object.assign(S.rp, { start: null, end: null });
const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
function rangeParams() {
  const p = new URLSearchParams({ include_test: $("#rpTest").checked });
  if (S.rp.days === "custom" && S.rp.start && S.rp.end) { p.set("start", S.rp.start); p.set("end", S.rp.end); }
  else p.set("days", S.rp.days === "custom" ? 7 : S.rp.days);
  return p;
}
function rangeBounds() {
  if (S.rp.days === "custom" && S.rp.start && S.rp.end) return [new Date(S.rp.start).getTime() / 1000, new Date(S.rp.end).getTime() / 1000 + 86400];
  const d = Number(S.rp.days) || 7;
  return [Date.now() / 1000 - d * 86400, Date.now() / 1000 + 60];
}

export async function loadReport() {
  let r;
  try { r = await api("/api/report?" + rangeParams()); } catch (e) { toast(e.message, true); return; }
  S.rp.data = r;
  const P = palette();
  const PR = r.protocols || {}, hs = r.health.map((h) => h.score), an = r.anomalies, acts = r.actions || [];
  const sev = { danger: 0, warning: 0, info: 0 };
  for (const a of an) sev[a.severity] = (sev[a.severity] || 0) + 1;
  const verified = acts.filter((x) => x.verification && x.verification.verified === true).length;
  const k = [["전체 패킷", num(PR.total), ""], ["전체 전송량", bytes(PR.bytes), ""], ["이상 징후", `${num(an.length)}건`, `위험 ${sev.danger} · 주의 ${sev.warning} · 정보 ${sev.info}`],
    ["위험 등급", `${num(sev.danger)}건`, an.length ? `${Math.round(sev.danger / an.length * 100)}%` : ""], ["실행한 조치", `${num(acts.length)}건`, acts.length ? `효과 검증 ${verified}건` : ""],
    ["평균 상태 점수", hs.length ? `${Math.round(hs.reduce((a, b) => a + b, 0) / hs.length)}점` : "-", hs.length ? `최저 ${Math.min(...hs)}점` : "기록 없음"]];
  $("#rpKpis").innerHTML = k.map(([a, b, c]) => `<div class="card kpi"><div class="kpi-label">${esc(a)}</div><div class="kpi-value ${b === "-" ? "wait" : ""}">${esc(b)}</div><div class="kpi-foot">${esc(c)}</div></div>`).join("");
  if (r.daily.length) {
    ensureChart("rpDaily");
    plot("rpDaily", [
      { type: "bar", name: "다운로드", x: r.daily.map((d) => d.day), y: r.daily.map((d) => d.down_bytes / 1e6), marker: { color: P.down }, hovertemplate: "↓ %{y:.1f} MB<extra></extra>" },
      { type: "bar", name: "업로드", x: r.daily.map((d) => d.day), y: r.daily.map((d) => d.up_bytes / 1e6), marker: { color: P.up }, hovertemplate: "↑ %{y:.1f} MB<extra></extra>" },
    ], { barmode: "stack", showlegend: true, legend: { orientation: "h", y: 1.12 }, yaxis: { title: { text: "MB", font: { size: 11 } } }, xaxis: { type: "category" } });
  } else emptyChart("rpDaily", "이 기간에 저장된 사용량이 없어요");
  if (r.health.length) {
    ensureChart("rpHealth");
    plot("rpHealth", [{ x: r.health.map((h) => new Date(h.ts * 1000)), y: r.health.map((h) => h.score), type: "scatter", mode: "lines", line: { color: P.ok, width: 2 }, hovertemplate: "%{y}점<extra></extra>" }],
      { yaxis: { range: [0, 105] }, shapes: [{ type: "line", xref: "paper", x0: 0, x1: 1, y0: 80, y1: 80, line: { color: P.warn, dash: "dot", width: 1 } },
        { type: "line", xref: "paper", x0: 0, x1: 1, y0: 50, y1: 50, line: { color: P.crit, dash: "dot", width: 1 } }] });
  } else emptyChart("rpHealth", "점수 기록이 없어요");
  const keys = ["TCP", "UDP", "ICMP", "OTHER"].filter((x) => PR[x]);
  if (keys.length) {
    ensureChart("rpProto");
    plot("rpProto", [{ type: "pie", hole: .6, labels: keys.map((x) => x === "OTHER" ? "기타" : x), values: keys.map((x) => PR[x]), sort: false,
      marker: { colors: keys.map((x) => ({ TCP: P.tcp, UDP: P.udp, ICMP: P.icmp, OTHER: P.other }[x])) }, textposition: "inside", insidetextorientation: "horizontal", textfont: { color: "#fff" }, hovertemplate: "%{label}: %{value:,}개<extra></extra>" }],
      { showlegend: true, legend: { orientation: "h" }, margin: { l: 8, r: 8, t: 8, b: 8 } });
  } else emptyChart("rpProto", "데이터 없음");
  drawReportIp();
  const ports = (r.ports || []).slice(0, 10).reverse();
  if (ports.length) {
    ensureChart("rpPort");
    plot("rpPort", [{ type: "bar", orientation: "h", y: ports.map((x) => `${x.service} (${x.proto})`), x: ports.map((x) => x.bytes), marker: { color: P.info }, text: ports.map((x) => bytes(x.bytes)), textposition: "outside", cliponaxis: false, hovertemplate: "%{y}: %{text}<extra></extra>" }],
      { margin: { l: 120, r: 64, t: 4, b: 20 }, xaxis: { showticklabels: false, showgrid: false }, yaxis: { automargin: true } });
  } else emptyChart("rpPort", "데이터 없음");
  // 위험 수준별 × 상태
  if (an.length) {
    ensureChart("rpSev");
    const statuses = ["active", "ended", "resolved", "dismissed"];
    const sevs = [["danger", "위험", P.crit], ["warning", "주의", P.warn], ["info", "정보", P.info]];
    plot("rpSev", sevs.map(([s, label, color]) => ({ type: "bar", name: label, x: statuses.map((st) => STATUS_KO[st]), y: statuses.map((st) => an.filter((a) => a.severity === s && a.status === st).length), marker: { color }, hovertemplate: `${label} %{y}건<extra></extra>` })),
      { barmode: "stack", showlegend: true, legend: { orientation: "h", y: 1.15 }, margin: { l: 36, r: 8, t: 8, b: 32 }, xaxis: { type: "category" } });
  } else emptyChart("rpSev", "이 기간에 탐지된 이상 징후가 없어요");
  // 탐지·대응 결과
  const title = (x) => (S.catalog && S.catalog.actions[x.action] || {}).title || x.action;
  $("#rpActSub").textContent = acts.length ? `${acts.length}건 · 자동 ${acts.filter((x) => x.trigger === "auto").length}건 · 시뮬레이션 ${acts.filter((x) => x.simulated).length}건 · 되돌림 ${acts.filter((x) => x.rolled_back_at).length}건` : "기간 내 실행한 조치가 없어요";
  $("#rpActions").innerHTML = acts.length ? `<thead><tr><th>시각</th><th>조치</th><th>실행</th><th>결과</th><th>검증</th></tr></thead><tbody>${acts.slice(0, 50).map((x) => {
    const v = x.verification || {};
    return `<tr ${x.anomaly_id ? `data-anom="${x.anomaly_id}"` : ""}><td>${dt(x.created_at)}</td><td>${esc(title(x))}</td><td>${x.trigger === "auto" ? `<span class="sev-badge s-warning">자동</span>` : "사용자"}</td>
      <td><span class="sev-badge ${x.rolled_back_at ? "s-info" : ["success", "simulated"].includes(x.status) ? (x.simulated ? "s-test" : "s-good") : "s-danger"}">${esc(x.rolled_back_at ? "되돌림" : ACT_STATUS[x.status] || x.status)}</span></td>
      <td>${v.verified === true ? `<span class="sev-text-ok">개선 확인</span>` : v.verified === false ? `<span class="sev-text-warning">미확인</span>` : "-"}</td></tr>`; }).join("")}</tbody>` : `<tbody><tr><td>${emptyHtml("🛠️", "조치 기록이 없어요")}</td></tr></tbody>`;
  $$("#rpActions [data-anom]").forEach((tr) => tr.onclick = () => { hooks.go("issues/" + tr.dataset.anom); });
  $("#rpAnomSub").textContent = r.packet_retention_oldest ? `IP·포트 통계는 보관 중인 패킷(${dt(r.packet_retention_oldest)} 이후) 기준이에요. 사용량은 분 단위 집계로 기간 전체를 보여줘요.` : "";
  $("#rpAnom").innerHTML = an.length ? `<thead><tr><th>탐지 시각</th><th>종류</th><th>위험</th><th>관련 IP</th><th>측정/기준</th><th>상태</th><th>출처</th></tr></thead><tbody>${an.map((a) =>
    `<tr data-anom="${a.id}"><td>${dt(a.detected_at)}</td><td>${esc(a.type_label)}</td><td>${sevPill(a.severity)}</td><td class="mono">${esc(a.src || a.dst || "-")}</td>
      <td class="mono">${esc(String(a.peak ?? a.measured))} / ${esc(String(a.threshold))}</td><td>${esc(STATUS_KO[a.status] || a.status)}</td><td>${srcPill(a.source) || "실제"}</td></tr>`).join("")}</tbody>`
    : `<tbody><tr><td>${emptyHtml("✅", "이 기간에 탐지된 이상 징후가 없어요")}</td></tr></tbody>`;
  $$("#rpAnom [data-anom]").forEach((tr) => tr.onclick = () => { hooks.go("issues"); S.is.filter = ""; $$("#isChips .chip").forEach((c) => c.classList.toggle("on", c.dataset.s === "")); selectIssue(+tr.dataset.anom); });
  loadLabSummary();
}
async function loadLabSummary() {
  const box = $("#rpLab");
  let d;
  try { d = await api("/api/lab/experiments?limit=500"); } catch (e) { box.innerHTML = `<div class="empty sm">실험실 기록을 불러오지 못했어요</div>`; return; }
  const [s0, s1] = rangeBounds();
  const ex = d.experiments.filter((e) => e.status === "completed" && e.created_at >= s0 && e.created_at < s1);
  if (!ex.length) { box.innerHTML = emptyHtml("🧪", "이 기간에 완료한 실험이 없어요", "실험실에서 시나리오를 실행하면 여기에 요약돼요"); return; }
  const atk = ex.filter((e) => e.kind !== "baseline");
  const mean = (arr) => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
  const by = {};
  for (const e of ex) { (by[e.scenario] = by[e.scenario] || { title: e.title, kind: e.kind, runs: 0, det: 0, lat: [], f1: [], fp: 0 }); const b = by[e.scenario]; b.runs++; if (e.detected) b.det++; if (e.latency_sec != null) b.lat.push(e.latency_sec); if (e.f1 != null) b.f1.push(e.f1); if (e.fp) b.fp++; }
  box.innerHTML = `<div class="metric-grid">
      <div class="metric"><div class="k">완료한 실험</div><div class="v">${num(ex.length)}<small>회</small></div></div>
      <div class="metric"><div class="k">탐지율 (공격·장애)</div><div class="v">${atk.length ? pct(atk.filter((e) => e.detected).length / atk.length) : "-"}</div></div>
      <div class="metric"><div class="k">평균 탐지 소요</div><div class="v">${mean(atk.filter((e) => e.latency_sec != null).map((e) => e.latency_sec)) != null ? mean(atk.filter((e) => e.latency_sec != null).map((e) => e.latency_sec)).toFixed(1) + "초" : "-"}</div></div>
      <div class="metric"><div class="k">평균 F1 · 오탐 실험</div><div class="v">${pct(mean(ex.filter((e) => e.f1 != null).map((e) => e.f1)))}<small> · ${ex.filter((e) => e.fp).length}회</small></div></div></div>
    <div class="table-wrap mt" style="max-height:260px"><table class="pk"><thead><tr><th>시나리오</th><th>실행</th><th>탐지율</th><th>평균 소요</th><th>평균 F1</th><th>오탐 발생</th></tr></thead><tbody>
      ${Object.values(by).map((b) => `<tr><td><b>${esc(b.title)}</b> <span class="sub-ip">${b.kind === "attack" ? "공격" : b.kind === "fault" ? "장애" : "기준선"}</span></td><td>${b.runs}</td><td>${b.kind === "baseline" ? "-" : pct(b.det / b.runs)}</td><td>${b.lat.length ? mean(b.lat).toFixed(1) + "초" : "-"}</td><td>${pct(mean(b.f1))}</td><td>${b.fp}/${b.runs}</td></tr>`).join("")}</tbody></table></div>
    <div class="sub-ip" style="margin-top:8px">합성 데이터 기준이에요. 생성기와 탐지기를 같은 프로젝트에서 설계해 실제 환경보다 좋게 나올 수 있어요.</div>`;
}
export function drawReportIp() {
  const r = S.rp.data; if (!r) return;
  const P = palette();
  const rows = (r[S.rp.ipKey] || []).slice(0, 10).reverse();
  if (!rows.length) { emptyChart("rpIp", "데이터 없음"); return; }
  ensureChart("rpIp");
  plot("rpIp", [{ type: "bar", orientation: "h", y: rows.map((x) => x.label), x: rows.map((x) => x.bytes), marker: { color: P.primary },
    text: rows.map((x) => bytes(x.bytes)), textposition: "outside", cliponaxis: false, customdata: rows.map((x) => x.ip), hovertemplate: "%{customdata}<br>%{text}<extra></extra>" }],
    { margin: { l: 140, r: 64, t: 4, b: 20 }, xaxis: { showticklabels: false, showgrid: false }, yaxis: { automargin: true, tickfont: { size: 11 } } });
}
export function exportCsv() {
  const kinds = [["packets", "패킷 목록", "저장된 패킷 요약 (최대 20만 개)"], ["traffic", "분 단위 사용량", "분마다 패킷 수·전송량·프로토콜"], ["anomalies", "이상 탐지 이력", "탐지 기준·측정값·근거 포함"],
    ["actions", "조치 기록", "실행·검증·롤백 결과"], ["health", "상태 점수 기록", "30초 단위 종합 점수와 감점 내역"]];
  const q = rangeParams().toString();
  modal(`<h3>CSV로 내보내기</h3><p class="card-sub">엑셀에서 바로 열 수 있어요. ${S.rp.days === "custom" ? `기간: ${S.rp.start} ~ ${S.rp.end}` : `기간: 최근 ${S.rp.days}일`}${$("#rpTest").checked ? " · 테스트 데이터 포함" : ""}</p>
    ${kinds.map(([k, t, d]) => `<div class="rec"><div class="rec-body"><div class="rec-title">${t}</div><div class="rec-why">${d}</div></div><a class="btn btn-tonal btn-sm" href="/api/export/${k}.csv?${q}" download>내려받기</a></div>`).join("")}
    <div class="sub-ip">실험실 결과는 실험실 탭의 "실험 이력 → CSV 내보내기"에서 따로 받아요(실제 데이터와 분리).</div>
    <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button></div>`);
}
export function bindReport() {
  $$("#rpSeg button").forEach((b) => b.onclick = () => {
    $$("#rpSeg button").forEach((x) => x.classList.toggle("on", x === b));
    S.rp.days = b.dataset.d === "custom" ? "custom" : +b.dataset.d;
    $("#rpRange").classList.toggle("hidden", S.rp.days !== "custom");
    if (S.rp.days === "custom") { if (!$("#rpEnd").value) { const e = new Date(), s = new Date(Date.now() - 6 * 86400000); $("#rpStart").value = ymd(s); $("#rpEnd").value = ymd(e); } S.rp.start = $("#rpStart").value; S.rp.end = $("#rpEnd").value; }
    loadReport();
  });
  $("#rpApply").onclick = () => { S.rp.start = $("#rpStart").value; S.rp.end = $("#rpEnd").value; if (!S.rp.start || !S.rp.end || S.rp.start > S.rp.end) { toast("시작일이 종료일보다 늦어요", true); return; } loadReport(); };
  $$("#rpIpSeg button").forEach((b) => b.onclick = () => { $$("#rpIpSeg button").forEach((x) => x.classList.toggle("on", x === b)); S.rp.ipKey = b.dataset.k; drawReportIp(); });
  $("#rpTest").onchange = loadReport;
  $("#rpCsv").onclick = exportCsv;
  $("#rpPdf").onclick = () => { toast("PDF를 만들고 있어요…"); window.location.href = `/api/export/report.pdf?${rangeParams()}`; };
}
