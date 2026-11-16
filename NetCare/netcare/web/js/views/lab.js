/* 가상 실험실(Simulation Lab) */
import { $, $$, api, esc, num, dt, tm, toast, pct, typeLabel } from "../core.js";
import { plot, ensureChart } from "../charts.js";
import { palette, alpha } from "../theme.js";
import { sevPill, modal, closeModal, emptyHtml } from "../ui.js";
import { openPacket } from "./packets.js";

export const LAB = { scenarios: [], actions: {}, sel: null, pane: "run", watching: null, lastResult: null, benchId: null, benchShown: null, history: [] };
/* 시나리오별 실험 목적·난이도(1~3). 난이도는 "탐지하기 얼마나 까다로운가"의 설계상 분류이고 성능 수치가 아니다. */
const LAB_META = {
  normal: { purpose: "정상 트래픽만으로 오탐(FP)이 없는지 확인", level: 1 }, ip_spoof: { purpose: "출발지 위조 징후 5종을 '의심'으로 잡는지", level: 2 },
  arp_spoof: { purpose: "IP-MAC 대응이 바뀌는 중간자 공격 징후", level: 1 }, dns_spoof: { purpose: "경합하는 가짜 DNS 응답을 구분하는지", level: 2 },
  port_scan: { purpose: "짧은 시간의 다중 포트 탐색 탐지", level: 1 }, syn_flood: { purpose: "완료되지 않는 연결 요청 폭주 탐지", level: 1 },
  repeated: { purpose: "같은 대상으로의 반복 연결 시도 탐지", level: 2 }, packet_loss: { purpose: "재전송·중복 ACK로 손실 추정", level: 3 },
  latency: { purpose: "핸드셰이크·DNS 왕복 시간 증가 탐지", level: 2 }, jitter: { purpose: "지연의 불규칙한 변동 탐지", level: 3 },
  dns_failure: { purpose: "DNS 오류·무응답 누적 탐지", level: 2 }, bandwidth: { purpose: "평탄한 처리량 + 지연 증가로 제한 '의심'", level: 3 },
  conn_failure: { purpose: "평소 쓰던 서버의 연속 실패 탐지", level: 2 },
};
const levelHtml = (n) => `<span class="lvl" title="설계상 난이도 ${n}/3">${[1, 2, 3].map((i) => `<i class="${i <= n ? "on" : ""}"></i>`).join("")}</span>`;
function expectHtml(id) {
  const h = LAB.history.filter((e) => e.scenario === id && e.status === "completed");
  if (!h.length) return `<b>예상 결과</b> 아직 실행 기록 없음`;
  const atk = h.filter((e) => e.kind !== "baseline");
  const lat = atk.filter((e) => e.latency_sec != null).map((e) => e.latency_sec);
  if (!atk.length) return `<b>지난 ${h.length}회</b> 오탐 ${h.filter((e) => e.fp).length}회`;
  return `<b>지난 ${h.length}회</b> 탐지 ${Math.round(atk.filter((e) => e.detected).length / atk.length * 100)}%${lat.length ? ` · 평균 ${(lat.reduce((a, b) => a + b, 0) / lat.length).toFixed(1)}초` : ""}`;
}

export async function loadLab() {
  if (!LAB.scenarios.length) {
    try { const d = await api("/api/lab/scenarios"); LAB.scenarios = d.scenarios; LAB.actions = d.actions; } catch (e) { toast(e.message, true); return; }
  }
  try { LAB.history = (await api("/api/lab/experiments?limit=300")).experiments; } catch (e) { /* 요약만 빠짐 */ }
  labPane(LAB.pane);
}
export function labPane(p) {
  LAB.pane = p;
  $$("#labSeg button").forEach((b) => b.classList.toggle("on", b.dataset.p === p));
  $("#labRunPane").classList.toggle("hidden", p !== "run");
  $("#labBenchPane").classList.toggle("hidden", p !== "bench");
  $("#labHistPane").classList.toggle("hidden", p !== "hist");
  if (p === "run") renderLabCards();
  if (p === "bench") renderBench();
  if (p === "hist") renderLabHist();
}
function renderLabCards() {
  const groups = [["baseline", "기준선 (오탐 측정)", "🌿"], ["attack", "공격 시뮬레이션", "🛡️"], ["fault", "네트워크 장애", "🔧"]];
  $("#labCards").innerHTML = groups.map(([k, t, ic]) => `<div class="lab-group-title">${ic} ${t}</div><div class="lab-grid">${LAB.scenarios.filter((s) => s.kind === k).map((s) =>
    `<div class="lab-card ${LAB.sel === s.id ? "sel" : ""}" data-sc="${esc(s.id)}"><div class="lc-icon">${s.icon}</div><div class="lc-title">${esc(s.title)}</div>
      <div class="lc-desc">${esc(s.desc)}</div>
      <div class="lc-meta"><span><b>목적</b> ${esc((LAB_META[s.id] || {}).purpose || "")}</span></div>
      <div class="lc-meta"><span><b>난이도</b> ${levelHtml((LAB_META[s.id] || {}).level || 1)}</span><span>${expectHtml(s.id)}</span></div>
      <div class="lc-foot">${s.expected.map((x) => `<span class="chip-mini">탐지: ${esc(typeLabel(x))}</span>`).join("")}
      ${s.certainty_note ? `<span class="chip-mini b-warn">의심 수준</span>` : ""}<span class="chip-mini">단계 A(Scapy)</span></div></div>`).join("")}</div>`).join("");
  $$("#labCards .lab-card").forEach((c) => c.onclick = () => { LAB.sel = c.dataset.sc; renderLabCards(); renderLabConfig(); });
}
function renderLabConfig() {
  const s = LAB.scenarios.find((x) => x.id === LAB.sel); if (!s) return;
  const d = s.defaults, box = $("#labConfig");
  box.classList.remove("hidden");
  box.innerHTML = `<div class="card-head"><div><div class="card-title">${s.icon} ${esc(s.title)} 실험 조건</div><div class="card-sub">같은 조건과 시드로 다시 실행하면 같은 결과가 나와요 (재현 가능).</div></div></div>
    ${s.certainty_note ? `<div class="box box-warn" style="margin-top:0">⚠️ ${esc(s.certainty_note)}</div>` : ""}
    <div class="box box-gray" style="margin-top:${s.certainty_note ? "8px" : "0"}"><b>실행하면 이렇게 돼요</b>${s.kind === "baseline" ? "공격·장애 없이 정상 통신만 흘러요. 탐지가 0건이어야 정상이고, 나오면 오탐으로 집계돼요."
      : `${d.attack_start}초까지 평소 통신으로 기준선을 학습한 뒤 ${d.attack_start}~${d.attack_end}초에 ${s.kind === "attack" ? "공격" : "장애"}가 들어가요. 기대 탐지: ${s.expected.map(typeLabel).join(", ")}${s.acceptable.length ? ` (함께 나올 수 있는 관련 징후: ${s.acceptable.map(typeLabel).join(", ")})` : ""}.`}
      ${expectHtml(s.id).replace(/<\/?b>/g, "")}</div>
    <div class="form-grid mt">
      <div class="form-row"><label>강도 <span id="lcIv">${d.intensity}</span>×</label><div class="range-row"><input type="range" id="lcI" min="0.1" max="3" step="0.05" value="${d.intensity}"></div>
        <div class="hint">1×는 탐지 기준의 약 3~5배. 0.25× 이하는 기준 아래라 놓치는 것이 정상이에요.</div></div>
      <div class="form-row"><label>시드 (재현용 난수값)</label><input class="input" id="lcSeed" type="number" value="${d.seed}"></div>
      <div class="form-row"><label>전체 길이(초)</label><input class="input" id="lcDur" type="number" value="${d.duration}"></div>
      <div class="form-row"><label>${s.kind === "fault" ? "장애" : s.kind === "attack" ? "공격" : "-"} 구간(초)</label><div style="display:flex;gap:8px"><input class="input" id="lcA0" type="number" value="${d.attack_start}"><input class="input" id="lcA1" type="number" value="${d.attack_end}"></div>
        <div class="hint">앞부분은 평소 상태(기준선) 학습 구간이에요.</div></div>
    </div>
    <label class="switch"><span>정상 배경 트래픽 섞기 (오탐 측정)${s.kind === "fault" ? " · 장애는 배경 통신에 영향을 주므로 항상 켜져요" : ""}</span><input type="checkbox" id="lcBg" ${d.background ? "checked" : ""} ${s.kind === "fault" ? "disabled" : ""}></label>
    <div class="form-grid">
      <div class="form-row"><label>실행 속도</label><div class="seg" id="lcSpeed"><button class="on" data-v="fast">빠르게</button><button data-v="realtime">실시간</button></div>
        <div class="hint">실시간은 1초에 1초씩 진행돼 그래프를 보며 가상 조치를 직접 누를 수 있어요.</div></div>
      <div class="form-row"><label>대응</label><div class="seg" id="lcPol"><button class="on" data-v="none">조치 없음</button><button data-v="auto">탐지 시 권장 가상 조치</button></div>
        <div class="hint">${s.remedy_title ? `권장: ${esc(s.remedy_title)}` : "권장 조치 없음"} · 조치 실험의 탐지 지표는 조치 시점까지만 계산해요.</div></div>
    </div>
    <div class="modal-actions" style="margin-top:8px"><button class="btn btn-sim" id="lcRun">▶ 실험 실행</button></div>`;
  $("#lcI").oninput = (e) => $("#lcIv").textContent = e.target.value;
  $$("#lcSpeed button, #lcPol button").forEach((b) => b.onclick = () => { $$(`#${b.parentElement.id} button`).forEach((x) => x.classList.toggle("on", x === b)); });
  $("#lcRun").onclick = async () => {
    const body = { scenario: s.id, params: { intensity: +$("#lcI").value, seed: +$("#lcSeed").value, duration: +$("#lcDur").value, attack_start: +$("#lcA0").value,
      attack_end: +$("#lcA1").value, background: $("#lcBg").checked }, realtime: $("#lcSpeed .on").dataset.v === "realtime", policy: $("#lcPol .on").dataset.v };
    try { const r = await api("/api/lab/run", { method: "POST", body }); LAB.watching = r.experiment_id; $("#labResult").classList.add("hidden"); toast("실험을 시작했어요"); labTick(); }
    catch (e) { toast(e.message, true); }
  };
}
function labChart(id, series, a0, a1, marks) {
  if (!series.length) return;
  const P = palette();
  ensureChart(id);
  const x = series.map((p) => p.s);
  const shapes = [{ type: "rect", xref: "x", yref: "paper", x0: a0, x1: a1, y0: 0, y1: 1, fillcolor: alpha(P.sim, .08), line: { width: 0 } }];
  for (const m of marks) shapes.push({ type: "line", xref: "x", yref: "paper", x0: m.s, x1: m.s, y0: 0, y1: 1, line: { color: m.color, width: 1.5, dash: m.dash || "dot" } });
  // 주석이 겹치지 않도록 번갈아 높이를 바꾼다 (탐지·조치 표시가 같은 초에 몰리는 경우)
  const ann = marks.map((m, i) => ({ x: m.s, y: 1 + (i % 2) * 0.09, yref: "paper", text: m.text, showarrow: false, font: { size: 10, color: m.color }, yanchor: "bottom", xanchor: i % 2 ? "left" : "right" }));
  plot(id, [
    { x, y: series.map((p) => p.total), name: "전체 패킷/초", type: "scatter", mode: "lines", line: { color: P.muted, width: 2 }, hovertemplate: "%{x}초 전체 %{y}<extra></extra>" },
    { x, y: series.map((p) => p.attack), name: "공격 패킷/초", type: "scatter", mode: "lines", fill: "tozeroy", line: { color: P.crit, width: 2 }, fillcolor: alpha(P.crit, .12), hovertemplate: "%{x}초 공격 %{y}<extra></extra>" },
    { x, y: series.map((p) => p.metric), name: "비교 지표", yaxis: "y2", type: "scatter", mode: "lines", line: { color: P.sim, width: 1.5, dash: "dash" }, hovertemplate: "%{x}초 지표 %{y}<extra></extra>" },
  ], { shapes, annotations: ann, showlegend: true, legend: { orientation: "h", y: -0.18 }, margin: { l: 44, r: 44, t: 36, b: 40 },
    xaxis: { title: { text: "실험 시간(초) · 보라색 음영 = 공격/장애 구간", font: { size: 11 } } }, yaxis2: { overlaying: "y", side: "right", showgrid: false, rangemode: "tozero", tickfont: { color: P.chartText } } });
}
function renderLabLive(st) {
  const P = palette();
  const x = st.experiment, box = $("#labLive");
  box.classList.remove("hidden");
  const marks = [];
  const seen = new Set();
  for (const d of x.detections) if (!seen.has(d.type)) { seen.add(d.type); marks.push({ s: d.sec, color: P.warn, text: `탐지: ${typeLabel(d.type)}` }); }
  for (const a of x.effects_log) marks.push({ s: a.sec + 1, color: P.ok, text: `조치: ${(LAB.actions[a.action] || {}).title || a.action}`, dash: "solid" });
  box.innerHTML = `<div class="card-head"><div><div class="card-title">⏱ 진행 중 · ${esc(x.title)} <span class="sev-badge s-sim">시뮬레이션</span></div>
      <div class="card-sub">${x.mode === "realtime" ? "실시간" : "빠르게"} · 대응 ${x.policy === "auto" ? "권장 가상 조치 자동" : "없음"} · ${x.sec + 1}/${x.duration}초</div></div>
      <div class="row">${x.mode === "realtime" ? `<button class="btn btn-secondary btn-sm" id="labPause">${x.paused ? "▶ 재개" : "⏸ 일시정지"}</button>` : ""}<button class="btn btn-secondary btn-sm" id="labStop">중지</button></div></div>
    <div class="steps-h">${[["기준선 학습", x.sec < x.attack_start, x.sec >= x.attack_start], [x.kind === "fault" ? "장애 구간" : x.kind === "attack" ? "공격 구간" : "정상 구간", x.sec >= x.attack_start && x.sec < x.attack_end, x.sec >= x.attack_end], ["유예·마무리", x.sec >= x.attack_end, false]]
      .map(([t, on, done], i, arr) => `<span class="st ${on ? "on" : ""} ${done ? "done" : ""}">${done ? "✓ " : ""}${t}</span>${i < arr.length - 1 ? `<span class="sep">›</span>` : ""}`).join("")}${x.paused ? `<span class="sev-badge s-warning">일시정지</span>` : ""}</div>
    <div class="progress sim"><div style="width:${((x.sec + 1) / x.duration) * 100}%"></div></div>
    <div class="chart" id="labLiveChart"></div>
    <div class="section-h">탐지 이력</div>
    ${x.detections.length ? `<ul class="feed">${x.detections.map((d) => `<li><div class="feed-dot" style="background:var(--warn-soft)">⚠️</div><div><div class="feed-text">${esc(typeLabel(d.type))} ${sevPill(d.severity)}</div><div class="feed-time">${d.sec}초에 탐지 (공격 시작 후 ${(d.sec - x.attack_start).toFixed(0)}초)</div></div></li>`).join("")}</ul>` : `<div class="empty sm">아직 탐지된 징후가 없어요</div>`}
    ${x.mode === "realtime" ? `<div class="section-h">가상 조치 (직접 실행)</div><div style="display:flex;gap:8px;flex-wrap:wrap">
      ${x.remedy && x.remedy !== "end_fault" ? `<button class="btn btn-tonal-ok btn-sm" data-la="${x.remedy}">${esc(x.remedy_title)}</button>` : ""}
      <button class="btn btn-secondary btn-sm" data-la="diagnose">가상망 연결 진단</button>
      ${x.kind === "fault" ? `<button class="btn btn-secondary btn-sm" data-la="end_fault">장애 주입 종료 (실험 제어)</button>` : ""}</div>` : ""}`;
  labChart("labLiveChart", x.series, x.attack_start, x.attack_end, marks);
  $("#labStop").onclick = async () => { await api("/api/lab/stop", { method: "POST", body: {} }); toast("실험을 중지했어요"); };
  const pb = $("#labPause");
  if (pb) pb.onclick = async () => { try { const r = await api("/api/lab/pause", { method: "POST", body: {} }); toast(r.paused ? "실험을 일시정지했어요" : "실험을 재개했어요"); labTick(); } catch (e) { toast(e.message, true); } };
  $$("#labLive [data-la]").forEach((b) => b.onclick = async () => {
    try { const r = await api("/api/lab/actions/execute", { method: "POST", body: { action: b.dataset.la, params: {} } }); toast(r.result.message); } catch (e) { toast(e.message, true); }
  });
}
function summarize(e, sc, p, r) {
  if (e.status !== "completed") return `실험이 ${e.status === "stopped" ? "중간에 중지" : "완료되지 않음"} 상태라 지표를 신뢰하기 어려워요.`;
  const parts = [];
  if (e.kind === "baseline") parts.push(e.fp ? `정상 트래픽만 흘렸는데 ${e.fp}초 동안 오탐이 나왔어요(${(e.false_alerts || []).map((f) => typeLabel(f.type)).join(", ")}).` : `정상 트래픽 ${p.duration}초 동안 오탐이 없었어요.`);
  else if (e.detected) parts.push(`${sc.title || e.title}(강도 ${p.intensity}×)을 ${p.kind === "fault" ? "장애" : "공격"} 시작 ${e.latency_sec}초 뒤에 탐지했어요.`);
  else parts.push(`${sc.title || e.title}(강도 ${p.intensity}×)을 탐지하지 못했어요. ${p.intensity < 1 ? "기준 아래 강도라 놓칠 수 있어요." : "탐지 규칙 보완이 필요할 수 있어요."}`);
  if (e.kind !== "baseline") parts.push(`Precision ${pct(e.precision)}, Recall ${pct(e.recall)}, 오탐 ${(e.false_alerts || []).length}건.`);
  if (r && r.comparison && r.comparison.before != null && r.comparison.after != null) parts.push(`${r.experiment_control ? "장애 주입을 종료" : "가상 조치"} 후 ${r.metric_label} ${r.comparison.before} → ${r.comparison.after}${r.success ? "으로 개선됐어요" : ", 개선되지 않았어요"}.`);
  parts.push("합성 데이터 기준이에요.");
  return parts.join(" ");
}
export async function showLabResult(eid) {
  let e;
  try { e = await api(`/api/lab/experiments/${eid}`); } catch (er) { toast(er.message, true); return; }
  const P = palette();
  LAB.lastResult = e;
  labPane("run");
  $("#labLive").classList.add("hidden");
  const box = $("#labResult"); box.classList.remove("hidden");
  const sc = LAB.scenarios.find((s) => s.id === e.scenario) || {};
  const p = e.params || {};
  const r = e.response;
  const det = e.kind === "baseline" ? (e.fp ? `<span class="sev-text-danger">오탐 ${e.fp}초</span>` : `<span class="sev-text-ok">오탐 없음</span>`)
    : e.detected ? `<span class="sev-text-ok">탐지됨</span>` : `<span class="sev-text-warning">미탐지</span>`;
  const marks = [];
  if (e.latency_sec != null) marks.push({ s: p.attack_start + e.latency_sec, color: P.warn, text: "첫 탐지" });
  if (r) marks.push({ s: r.at_sec, color: P.ok, text: `조치: ${r.first_action_title}`, dash: "solid" });
  const ev = e.evidence, dg = e.diagnosis;
  box.innerHTML = `<div class="card-head"><div><div class="card-title">📋 실험 #${e.id} 결과 · ${sc.icon || ""} ${esc(e.title)} <span class="sev-badge s-sim">합성 데이터</span></div>
      <div class="card-sub">강도 ${p.intensity}× · 시드 ${p.seed} · ${p.duration}초 (구간 ${p.attack_start}~${p.attack_end}초) · 배경 ${p.background ? "있음" : "없음"} · ${e.mode === "realtime" ? "실시간" : "빠르게"} · ${e.status === "completed" ? "완료" : esc(e.status)}</div></div>
      <div style="display:flex;gap:6px"><a class="btn btn-secondary btn-sm" href="/api/lab/experiments/${e.id}/pcap" download>PCAP</a><button class="btn btn-secondary btn-sm" id="lrPk">패킷 보기</button><button class="btn btn-secondary btn-sm" id="lrAgain">같은 조건 재실행</button></div></div>
    <div class="metric-grid">
      <div class="metric"><div class="k">NetCare 판정</div><div class="v">${det}</div></div>
      <div class="metric"><div class="k">탐지 소요 시간</div><div class="v">${e.latency_sec != null ? e.latency_sec + "초" : "-"}</div></div>
      <div class="metric"><div class="k">생성 패킷 (공격·장애 표시)</div><div class="v">${num(e.packets)} <small>(${num(e.attack_packets)})</small></div></div>
      <div class="metric"><div class="k">오탐 알림</div><div class="v">${(e.false_alerts || []).length}건</div></div>
      <div class="metric"><div class="k">Precision</div><div class="v">${pct(e.precision)}</div></div>
      <div class="metric"><div class="k">Recall</div><div class="v">${pct(e.recall)}</div></div>
      <div class="metric"><div class="k">F1-score</div><div class="v">${pct(e.f1)}</div></div>
      <div class="metric"><div class="k">False Positive Rate</div><div class="v">${pct(e.fpr)}</div></div>
    </div>
    <div class="summary-box">${esc(summarize(e, sc, p, r))}</div>
    <div class="card-sub" style="margin-top:8px">1초 단위 판정: TP ${e.tp} · FN ${e.fn} · FP ${e.fp} · TN ${e.tn}${r ? " · 조치 이후는 지표에서 제외" : ""}. 합성 데이터 기준 지표예요.</div>
    <div class="tl">${(e.timeline || []).map((t) => `<span class="${t.mark === "-" ? "-" : t.mark}" title="${t.s}초: ${t.mark}${t.active.length ? " · " + esc(t.active.map(typeLabel).join(", ")) : ""}"></span>`).join("")}</div>
    <div class="legend-row"><span><i style="background:var(--ok)"></i>TP 공격 중 탐지</span><span><i style="background:var(--warn)"></i>FN 공격 중 미탐</span><span><i style="background:var(--crit)"></i>FP 오탐</span><span><i style="background:var(--surface-3)"></i>TN 정상</span><span><i style="background:var(--surface-2);border:1px dashed var(--border)"></i>유예(탐지 창 잔여)</span><span><i style="background:var(--sim-soft)"></i>조치 이후(지표 제외)</span></div>
    <div class="chart mt" id="labResChart"></div>
    ${ev ? `<div class="section-h">탐지 근거</div><div class="gauge"><div style="font-size:var(--fs-sm)"><b>${esc(typeLabel(ev.type))}</b> ${sevPill(ev.severity)} · ${esc(ev.criterion)}</div>
      <div class="card-sub" style="margin:6px 0 0">기준 ${esc(String(ev.threshold))} · 최고 측정값 ${esc(String(ev.peak))}</div>
      <details class="more"><summary>원본 근거 보기</summary><div class="code">${esc(JSON.stringify(ev.evidence, null, 2))}</div></details></div>` : ""}
    ${dg ? `<div class="section-h">진단 결과</div><div class="box box-gray" style="margin-top:0"><b>${esc(dg.title || "")} ${dg.certainty ? `· ${esc(dg.certainty)}` : ""}</b>${esc(dg.summary || "")}
      ${dg.recommendations && dg.recommendations.length ? `<div style="margin-top:6px">권장: ${esc(dg.recommendations.join(" / "))}</div>` : ""}</div>` : ""}
    ${r ? `<div class="section-h">조치 전후 비교 · ${esc(r.first_action_title)} (${r.at_sec}초, ${r.actions[0].trigger === "auto" ? "자동" : "직접"})</div>
      ${r.comparison && r.comparison.before != null && r.comparison.after != null ? `<div class="ba"><div class="side"><div class="k">조치 전 (${r.comparison.before_range ? r.comparison.before_range.join("~") + "초" : ""})</div><div class="v">${r.comparison.before}</div></div>
        <div style="font-size:22px" class="${r.success ? "sev-text-ok" : "sev-text-danger"}">→</div>
        <div class="side"><div class="k">조치 후 (${r.comparison.after_range ? r.comparison.after_range.join("~") + "초" : ""})</div><div class="v ${r.success ? "sev-text-ok" : "sev-text-danger"}">${r.comparison.after}</div></div></div>
        <div class="card-sub" style="margin-top:6px">지표: ${esc(r.metric_label)}${r.comparison.change_pct != null ? ` · 변화 ${r.comparison.change_pct}%` : ""} · ${r.success ? "개선됨" : "개선 안 됨"}
        ${r.anomaly_continued_after ? " · 조치 후에도 징후 탐지는 계속됨(예: 들어오는 공격 패킷은 방화벽 앞에서 캡처되므로)" : ""}</div>` : `<div class="box box-gray">${esc((r.comparison || {}).note || "비교할 수 없어요")}</div>`}
      <div class="box ${r.experiment_control ? "box-warn" : "box-gray"}">${esc(r.note)}</div>` : ""}
    ${(e.false_alerts || []).length ? `<div class="section-h">오탐으로 분류된 알림</div><table class="mini-table"><tr><th>유형</th><th>위험</th><th>시점</th><th>이유</th></tr>${e.false_alerts.map((f) => `<tr><td>${esc(typeLabel(f.type))}</td><td>${sevPill(f.severity)}</td><td>${f.at_sec}초</td><td>${esc(f.reason)}</td></tr>`).join("")}</table>` : ""}`;
  labChart("labResChart", e.series || [], p.attack_start, p.attack_end, marks);
  $("#lrAgain").onclick = async () => { try { const x = await api("/api/lab/run", { method: "POST", body: { scenario: e.scenario, params: p, realtime: e.mode === "realtime", policy: e.response_policy } }); LAB.watching = x.experiment_id; labTick(); } catch (er) { toast(er.message, true); } };
  $("#lrPk").onclick = () => openLabPackets(e.id);
}
async function openLabPackets(eid) {
  const d = await api(`/api/lab/packets?experiment_id=${eid}&limit=300`);
  modal(`<h3>실험 #${eid} 패킷 (최근 300개)</h3><p class="card-sub">가상 패킷도 실제 패킷과 같은 파서로 해석해요. 누르면 계층 구조를 볼 수 있어요.</p>
    <div class="table-wrap" style="max-height:60vh"><table class="pk"><thead><tr><th>시간</th><th>보내는 장치 → 받는 장치</th><th>종류</th><th>설명</th></tr></thead><tbody>
    ${d.packets.map((r) => `<tr data-lp="${r.id}"><td class="mono">${tm(r.ts)}</td><td>${esc(r.src_label)} → ${esc(r.dst_label)}</td><td><span class="proto p-${esc(r.proto)}">${esc(r.service || r.proto)}</span></td><td>${esc(r.friendly)}</td></tr>`).join("")}</tbody></table></div>
    <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button></div>`, true);
  $$("#modalCard [data-lp]").forEach((tr) => tr.onclick = () => { closeModal(); openPacket(+tr.dataset.lp, true); });
}
export async function labTick() {
  let st;
  try { st = await api("/api/lab/status"); } catch (e) { return; }
  if (st.running && st.experiment) {
    if (LAB.pane === "run") renderLabLive(st);
    LAB.watching = st.experiment.id;
  } else if (LAB.watching && !(st.benchmark && st.benchmark.status === "running")) {
    const id = LAB.watching; LAB.watching = null;
    setTimeout(() => showLabResult(id), 300);
  }
  if (st.benchmark && LAB.pane === "bench") renderBenchProgress(st.benchmark);
}
function renderBench() {
  const box = $("#labBenchPane");
  box.innerHTML = `<div class="card"><div class="card-title">📊 벤치마크: 반복 실행 + 강도 단계</div>
    <div class="card-sub">모든 시나리오를 여러 시드·강도로 반복해 시나리오별 탐지율, 탐지 소요 시간, Precision·Recall·F1·FPR을 계산해요. 대응 조치 없이, 정상 배경 트래픽을 섞어 실행해요.</div>
    <div class="form-grid"><div class="form-row"><label>강도 단계</label><div class="chips" id="bnI">${[0.25, 0.5, 1, 2].map((v) => `<button class="chip ${v === 1 ? "on" : ""}" data-v="${v}">${v}×</button>`).join("")}</div></div>
      <div class="form-row"><label>시드 개수 (반복 횟수)</label><input class="input" id="bnSeeds" type="number" min="1" max="10" value="3"></div></div>
    <div class="box box-gray" style="margin-top:0">예상 시간: 실험 1회당 약 3초. 강도 1단계 × 시드 3개면 13개 시나리오 × 3 = 39회(약 2분).</div>
    <div class="modal-actions"><button class="btn btn-sim" id="bnRun">벤치마크 실행</button></div>
    <div id="bnProg"></div></div><div id="bnResult"></div><div class="card mt"><div class="card-title">이전 벤치마크</div><div id="bnList" class="card-sub">불러오는 중…</div></div>`;
  $$("#bnI .chip").forEach((c) => c.onclick = () => c.classList.toggle("on"));
  $("#bnRun").onclick = async () => {
    const intensities = $$("#bnI .chip.on").map((c) => +c.dataset.v);
    const n = Math.max(1, Math.min(10, +$("#bnSeeds").value || 3));
    if (!intensities.length) { toast("강도를 하나 이상 고르세요", true); return; }
    try { const r = await api("/api/lab/benchmark", { method: "POST", body: { intensities, seeds: Array.from({ length: n }, (_, i) => i + 1) } }); LAB.benchId = r.benchmark_id; toast("벤치마크를 시작했어요"); }
    catch (e) { toast(e.message, true); }
  };
  api("/api/lab/benchmarks").then((d) => {
    $("#bnList").innerHTML = d.benchmarks.length ? `<table class="mini-table"><tr><th>#</th><th>시작</th><th>상태</th><th>진행</th><th>설정</th></tr>${d.benchmarks.map((b) =>
      `<tr data-bn="${b.id}"><td>${b.id}</td><td>${dt(b.created_at)}</td><td>${esc(b.status)}</td><td>${b.progress}/${b.total}</td><td>강도 ${esc((b.config.intensities || []).join(", "))} · 시드 ${(b.config.seeds || []).length}개</td></tr>`).join("")}</table>` : "아직 없어요";
    $$("#bnList [data-bn]").forEach((tr) => tr.onclick = () => showBench(+tr.dataset.bn));
  });
  if (LAB.benchId) showBench(LAB.benchId);
}
function renderBenchProgress(b) {
  const el = $("#bnProg"); if (!el) return;
  el.innerHTML = `<div class="progress sim"><div style="width:${(b.progress / Math.max(1, b.total)) * 100}%"></div></div><div class="card-sub">${b.status === "running" ? "실행 중" : "완료"} · ${b.progress}/${b.total}회</div>`;
  if (b.status !== "running" && LAB.benchShown !== b.id + ":" + b.status) { LAB.benchShown = b.id + ":" + b.status; LAB.benchId = b.id; showBench(b.id); }
}
async function showBench(bid) {
  let b;
  try { b = await api(`/api/lab/benchmarks/${bid}`); } catch (e) { return; }
  const s = b.summary, o = s.overall;
  const curve = s.intensity_curve || {};
  $("#bnResult").innerHTML = `<div class="card mt"><div class="card-title">결과 · 벤치마크 #${b.id} <span class="sev-badge s-sim">합성 데이터</span></div>
    <div class="card-sub">${esc(s.note)} 실험 ${s.experiments}회 · 1초 단위 합산.</div>
    <div class="metric-grid"><div class="metric"><div class="k">전체 Precision</div><div class="v">${pct(o.precision)}</div></div><div class="metric"><div class="k">전체 Recall</div><div class="v">${pct(o.recall)}</div></div>
      <div class="metric"><div class="k">전체 F1</div><div class="v">${pct(o.f1)}</div></div><div class="metric"><div class="k">전체 FPR</div><div class="v">${pct(o.fpr)}</div></div></div>
    <div class="table-wrap mt"><table class="pk"><thead><tr><th>시나리오</th><th>실행</th><th>탐지율</th><th>평균 소요</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>오탐 발생 실행</th></tr></thead><tbody>
    ${s.by_scenario.map((r) => `<tr><td><b>${esc(r.title || r.scenario)}</b> <span class="sub-ip">${r.kind === "attack" ? "공격" : r.kind === "fault" ? "장애" : "기준선"}</span></td><td>${r.runs}</td>
      <td>${r.detection_rate == null ? "-" : pct(r.detection_rate)}</td><td>${r.mean_latency_sec == null ? "-" : r.mean_latency_sec + "초"}</td><td>${pct(r.precision)}</td><td>${pct(r.recall)}</td><td>${pct(r.f1)}</td><td>${pct(r.fpr)}</td><td>${r.false_alert_runs}/${r.runs}</td></tr>`).join("")}</tbody></table></div>
    ${Object.keys(curve).length && Object.values(curve).some((c) => Object.keys(c).length > 1) ? `<div class="section-h">강도별 탐지율</div><div class="chart lg" id="bnCurve"></div>` : ""}</div>`;
  if ($("#bnCurve")) {
    const names = Object.keys(curve);
    plot("bnCurve", names.map((n) => ({ x: Object.keys(curve[n]).map(Number), y: Object.values(curve[n]).map((v) => v * 100), name: (LAB.scenarios.find((x) => x.id === n) || {}).title || n,
      type: "scatter", mode: "lines+markers", hovertemplate: "%{x}× → %{y:.0f}%<extra>" + n + "</extra>" })),
      { showlegend: true, legend: { orientation: "h", y: -0.25 }, xaxis: { title: { text: "강도(×)", font: { size: 11 } }, type: "log" }, yaxis: { title: { text: "탐지율 %", font: { size: 11 } }, range: [-5, 105] }, margin: { l: 50, r: 10, t: 10, b: 60 } });
  }
}
async function renderLabHist() {
  let d;
  try { d = await api("/api/lab/experiments?limit=200"); } catch (e) { toast(e.message, true); return; }
  $("#labHistPane").innerHTML = `<div class="card"><div class="card-head"><div><div class="card-title">실험 이력</div><div class="card-sub">모든 실험은 simlab.db 에만 저장돼요. 행을 누르면 결과를 다시 볼 수 있어요.</div></div>
    <a class="btn btn-secondary btn-sm" href="/api/lab/export/experiments.csv" download>CSV 내보내기</a></div>
    <div class="table-wrap"><table class="pk"><thead><tr><th>#</th><th>시각</th><th>시나리오</th><th>조건</th><th>판정</th><th>소요</th><th>P / R / F1 / FPR</th><th>오탐</th><th>대응</th></tr></thead><tbody>
    ${d.experiments.map((e) => `<tr data-ex="${e.id}"><td>${e.id}</td><td>${dt(e.created_at)}</td><td><b>${esc(e.title)}</b>${e.benchmark_id ? ` <span class="sub-ip">벤치 #${e.benchmark_id}</span>` : ""}</td>
      <td class="sub-ip">${(e.params || {}).intensity}× · 시드 ${(e.params || {}).seed}</td>
      <td>${e.status !== "completed" ? esc(e.status) : e.kind === "baseline" ? (e.fp ? "오탐 있음" : "오탐 없음") : e.detected ? "탐지" : "미탐지"}</td><td>${e.latency_sec != null ? e.latency_sec + "초" : "-"}</td>
      <td class="mono">${pct(e.precision)} / ${pct(e.recall)} / ${pct(e.f1)} / ${pct(e.fpr)}</td><td>${(e.false_alerts || []).length}</td><td>${e.response_policy === "auto" ? "자동" : "-"}</td></tr>`).join("") || `<tr><td colspan="9">${emptyHtml("🧪", "아직 실험이 없어요")}</td></tr>`}</tbody></table></div></div>`;
  $$("#labHistPane [data-ex]").forEach((tr) => tr.onclick = () => showLabResult(+tr.dataset.ex));
}
export function bindLab() {
  $$("#labSeg button").forEach((b) => b.onclick = () => labPane(b.dataset.p));
}
