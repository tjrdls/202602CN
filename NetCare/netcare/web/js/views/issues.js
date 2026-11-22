/* 문제 해결: 이상 징후 목록·상세·조치 실행·되돌리기 */
import { S, $, $$, api, esc, num, rate, dt, ago, toast, hooks, STATUS_KO, ACT_STATUS, TYPE_ICON } from "../core.js";
import { sevPill, srcPill, modal, closeModal, loadingHtml, errorHtml, emptyHtml } from "../ui.js";
import { ipLink } from "../ipdetail.js";

export async function loadIssues() {
  try {
    const d = await api("/api/anomalies?limit=400");
    S.is.list = d.anomalies;
    renderIssueList();
    if (!S.is.sel && !location.hash.includes("/")) {
      const first = S.is.list.find((a) => ["active", "ended"].includes(a.status));
      if (first) selectIssue(first.id);
    }
    if (S.is.sel) {
      const cur = S.is.list.find((a) => a.id === S.is.sel);
      if (cur && S.is.detail && (cur.last_seen !== S.is.detail.last_seen || cur.status !== S.is.detail.status)) selectIssue(S.is.sel, true);
    }
  } catch (e) { if (e.offline) hooks.showOffline(); }
}
export function renderIssueList() {
  const f = S.is.filter;
  const rows = S.is.list.filter((a) => f === "open" ? ["active", "ended"].includes(a.status) : f ? a.status === f : true);
  const cnt = (fn) => S.is.list.filter(fn).length;
  const counts = { open: cnt((a) => ["active", "ended"].includes(a.status)), "": S.is.list.length, resolved: cnt((a) => a.status === "resolved"), dismissed: cnt((a) => a.status === "dismissed") };
  $$("#isChips .chip").forEach((c) => { const n = counts[c.dataset.s]; c.innerHTML = `${esc(c.dataset.label || (c.dataset.label = c.textContent.replace(/\s*\d+$/, "")))}${n ? ` <span class="sub-ip" style="color:inherit;opacity:.7">${n}</span>` : ""}`; });
  $("#issueList").innerHTML = rows.length ? rows.map((a) => {
    const e = a.explanation || {};
    return `<div class="issue-item sev-${a.severity} ${S.is.sel === a.id ? "sel" : ""}" data-id="${a.id}">
      <div class="it-title">${TYPE_ICON[a.type] || "⚠️"} ${esc(e.title || a.type_label)}</div>
      <div class="it-meta">${sevPill(a.severity)}${srcPill(a.source)}<span>${esc(STATUS_KO[a.status] || a.status)}</span>·<span>${ago(a.last_seen)}</span>${a.count > 1 ? `·<span>${num(a.count)}회 감지</span>` : ""}</div></div>`;
  }).join("") : `<div class="card">${emptyHtml("✅", f === "open" ? "확인이 필요한 이상 징후가 없어요" : "해당하는 기록이 없어요")}</div>`;
  $$("#issueList .issue-item").forEach((el) => el.onclick = () => selectIssue(+el.dataset.id));
}
export async function selectIssue(id, silent = false) {
  S.is.sel = id;
  renderIssueList();
  if (!silent) $("#issueDetail").innerHTML = loadingHtml();
  try { S.is.detail = await api(`/api/anomalies/${id}`); } catch (e) { $("#issueDetail").innerHTML = errorHtml(e.message); return; }
  renderIssueDetail();
}
function gaugeHtml(a) {
  const m = Number(a.peak ?? a.measured), t = Number(a.threshold);
  if (!t || isNaN(m)) return "";
  const isRatio = t <= 1 && m <= 1;
  const max = Math.max(m, t) * 1.25;
  const pct = Math.min(100, (m / max) * 100), tp = (t / max) * 100;
  const fmtv = (v) => isRatio ? `${Math.round(v * 100)}%` : ["traffic_surge"].includes(a.type) ? rate(v) : num(Math.round(v * 10) / 10);
  return `<div class="gauge"><div style="font-size:var(--fs-sm)"><b>탐지 기준</b> · ${esc(a.criterion)}</div>
    <div class="gauge-bar"><div class="gauge-fill sev-${esc(a.severity)}" style="width:${pct}%"></div><div class="gauge-mark" style="left:${tp}%"><span>기준 ${esc(fmtv(t))}</span></div></div>
    <div class="gauge-legend"><span>실제 측정값(최고) <b class="sev-text-${esc(a.severity)}">${esc(fmtv(m))}</b></span><span>기준 대비 ${(m / t).toFixed(1)}배</span></div></div>`;
}
/* 유형별 "평소에는 이렇다"는 설명 (정상 상황과의 차이 블록) */
const NORMAL_HINT = {
  syn_surge: "정상적인 프로그램은 연결 요청(SYN) 대부분을 끝까지 완료해요. 완료율이 30% 아래로 떨어지는 일은 드물어요.",
  ip_packet_flood: "한 장치가 1초에 보내는 패킷은 보통 수십~수백 개예요. 대용량 전송 중에도 상대가 응답(ACK)을 돌려줘요.",
  port_concentration: "여러 서비스가 섞여 쓰이는 것이 보통이에요. 한 포트가 대부분을 차지하면 특정 서비스 집중 또는 공격 패턴일 수 있어요.",
  traffic_surge: "평소 사용량은 EWMA 기준선 주변에서 움직여요. 기준선 대비 표준편차 4배 이상의 급증은 드물어요.",
  repeated_connection: "같은 목적지·포트로 짧은 시간에 반복 연결하는 일은 보통 없어요. 연결이 완료되면 정상적인 폴링일 수 있어요.",
  port_scan: "한 장치가 짧은 시간에 수십 개의 서로 다른 포트·목적지를 두드리는 일은 정상 사용에서는 거의 없어요.",
  heavy_peer: "특정 상대와의 통신량이 전체의 대부분을 차지하는 경우는 대용량 다운로드·백업·스트리밍일 때예요.",
  dns_failure: "DNS 질의는 거의 항상 몇십 ms 안에 성공해요. 오류·무응답이 연달아 나오면 DNS 서버나 회선 문제예요.",
  gateway_unreachable: "공유기 ping은 손실 0%, 1~5ms가 보통이에요.",
  packet_loss: "평상시 손실률은 0~1% 수준이에요.",
  high_latency: "집·사무실 회선의 인터넷 ping은 보통 5~50ms예요.",
  arp_spoof: "한 IP에는 한 MAC 주소가 대응해요. 짧은 시간에 MAC이 번갈아 바뀌는 일은 장비 교체·DHCP 재할당 외에는 거의 없어요.",
  ip_spoof_suspect: "내 IP로 들어오는 패킷은 없어야 하고, LAN 장치의 IP-MAC 대응과 TTL은 안정적이에요.",
  dns_spoof_suspect: "같은 질의에 서로 다른 응답이 오거나 설정한 DNS 서버가 아닌 곳에서 응답이 오는 일은 정상 환경에서는 없어요.",
  latency_rise: "연결·조회 지연은 평소 기준선 근처에서 움직여요.",
  jitter_high: "연속 응답의 지연 차이(지터)는 평소 수 ms 수준이에요.",
  tcp_loss: "재전송·중복 ACK는 전체 세그먼트의 1% 미만이 보통이에요.",
  connection_failure: "평소 잘 응답하던 서버는 연속으로 실패하지 않아요.",
  bandwidth_limit_suspect: "속도 제한이 없으면 처리량은 자연스럽게 출렁이고, 지연도 함께 늘지 않아요.",
};
function fmtMeasure(a, v) {
  if (v == null || isNaN(Number(v))) return "-";
  const t = Number(a.threshold);
  if (t <= 1 && Number(v) <= 1) return `${Math.round(Number(v) * 100)}%`;
  if (a.type === "traffic_surge") return rate(v);
  return num(Math.round(Number(v) * 10) / 10);
}
function compareHtml(a) {
  const ev = a.evidence || {};
  const now = a.peak ?? a.measured;
  let base = null, baseLabel = "탐지 기준", baseDesc = NORMAL_HINT[a.type] || "";
  if (ev.baseline_mean_bps != null) { base = rate(ev.baseline_mean_bps); baseLabel = "평소 평균 사용량"; }
  else if (ev.baseline_ms != null) { base = `${ev.baseline_ms} ms`; baseLabel = "평소 지연"; }
  else if (ev.baseline_jitter_ms != null) { base = `${ev.baseline_jitter_ms} ms`; baseLabel = "평소 지터"; }
  else if (a.threshold) base = fmtMeasure(a, a.threshold);
  if (base == null && now == null) return "";
  const ratio = a.threshold && now != null && Number(a.threshold) > 0 ? (Number(now) / Number(a.threshold)) : null;
  return `<div class="compare"><div class="cmp"><div class="k">${esc(baseLabel)}</div><div class="v">${esc(base ?? "-")}</div><div class="d">${esc(baseDesc)}</div></div>
    <div class="mid">→</div>
    <div class="cmp now sev-${esc(a.severity)}"><div class="k">지금 측정값${a.peak != null ? " (최고)" : ""}</div><div class="v">${esc(fmtMeasure(a, now))}</div>
      <div class="d">${ratio != null ? `기준의 ${ratio.toFixed(1)}배` : ""}${a.count > 1 ? ` · ${num(a.count)}회 반복 감지` : ""}${a.criterion ? ` · ${esc(a.criterion)}` : ""}</div></div></div>`;
}
function timelineHtml(a) {
  const ev = [];
  const titleOf = (x) => (S.catalog && S.catalog.actions[x.action] || {}).title || x.action;
  ev.push({ ts: a.detected_at, cls: { danger: "crit", warning: "warn", info: "info" }[a.severity] || "info", t: "처음 탐지", d: a.criterion ? `기준: ${a.criterion}` : "" });
  for (const x of a.actions || []) {
    const ok = ["success", "simulated"].includes(x.status);
    ev.push({ ts: x.created_at, cls: x.simulated ? "sim" : ok ? "ok" : "crit", t: `${x.trigger === "auto" ? "자동 " : ""}조치: ${titleOf(x)}`,
      d: `${ACT_STATUS[x.status] || x.status}${(x.result || {}).message ? " · " + x.result.message : ""}` });
    const v = x.verification || {};
    if (v.message && v.verified != null) ev.push({ ts: v.checked_at || x.created_at + 0.5, cls: v.verified ? "ok" : "warn", t: v.verified ? "효과 검증됨" : "효과 미확인", d: v.message });
    if (x.rolled_back_at) ev.push({ ts: x.rolled_back_at, cls: "primary", t: "되돌림", d: (x.rollback_result || {}).message || "" });
  }
  if (a.last_seen && a.last_seen > a.detected_at + 1) ev.push({ ts: a.last_seen, cls: a.status === "active" ? "warn" : "info", t: a.status === "active" ? "마지막 감지 (진행 중)" : "마지막 감지", d: `${num(a.count)}회 누적` });
  if (a.status === "resolved") ev.push({ ts: a.last_seen + 0.1, cls: "ok", t: "조치 완료로 종료", d: "" });
  if (a.status === "dismissed") ev.push({ ts: a.last_seen + 0.1, cls: "ok", t: "정상 통신으로 처리", d: "사용자가 정상으로 표시했어요" });
  if (a.status === "ended") ev.push({ ts: a.last_seen + 0.1, cls: "info", t: "더 이상 감지되지 않음", d: "" });
  ev.sort((x, y) => x.ts - y.ts);
  return `<ul class="timeline">${ev.map((e) => `<li class="${e.cls}"><span class="tl-t">${esc(e.t)}<span class="tl-time">${dt(e.ts)}</span></span>${e.d ? `<div class="tl-d">${esc(e.d)}</div>` : ""}</li>`).join("")}</ul>`;
}
const dur = (s) => s < 60 ? `${Math.round(s)}초` : s < 3600 ? `${Math.round(s / 60)}분` : `${(s / 3600).toFixed(1)}시간`;

export function renderIssueDetail() {
  const a = S.is.detail; if (!a) return;
  const e = a.explanation || {}, an = e.analysis || {};
  const recs = (e.recommendations || []).map((r, i) => {
    const spec = S.catalog && r.action ? S.catalog.actions[r.action] : null;
    const tags = spec ? (spec.changes_system ? `<span class="tag tag-change">설정 변경</span>` : `<span class="tag tag-safe">안전</span>`) + (spec.requires_admin ? `<span class="tag tag-admin">관리자</span>` : "") : "";
    return `<div class="rec"><div class="rec-num">${i + 1}</div><div class="rec-body"><div class="rec-title">${esc(r.title)}${tags}</div><div class="rec-why">${esc(r.why)}</div></div>
      ${r.action ? `<button class="btn ${spec && spec.changes_system ? "btn-secondary" : "btn-tonal"} btn-sm" data-rec="${i}">${spec && spec.changes_system ? "검토하기" : "실행"}</button>` : `<span class="sub-ip">직접 확인</span>`}</div>`;
  }).join("");
  const evid = a.evidence || {};
  const hist = (a.actions || []).map(histHtml).join("");
  const ipMain = a.src || a.dst;
  const sim = a.source === "sim" || a.source === "test";
  const ipHtml = ipMain ? (sim ? `<span class="mono">${esc(ipMain)}</span>` : ipLink(ipMain)) : "-";
  const lastAct = (a.actions || []).find((x) => ["success", "simulated"].includes(x.status) && !x.rolled_back_at);
  const after = lastAct ? (lastAct.verification && lastAct.verification.verified === true ? "개선 확인됨" : lastAct.verification && lastAct.verification.verified === false ? "개선 미확인" : (a.status === "resolved" ? "조치 완료" : "검증 대기")) : null;
  $("#issueDetail").innerHTML = `
    <div class="detail-hero"><div class="detail-icon sev-${esc(a.severity)}">${TYPE_ICON[a.type] || "⚠️"}</div>
      <div style="flex:1;min-width:0"><div>${sevPill(a.severity)} ${srcPill(a.source)} <span class="sub-ip">${esc(e.type_label || "")} · ${esc(STATUS_KO[a.status] || a.status)}${e.certainty_label ? " · " + esc(e.certainty_label) : ""}</span>${e.analysis_status_label ? ` <span class="sev-badge ${e.analysis_status === "confirmed" ? "s-good" : "s-warning"}">${esc(e.analysis_status_label)}</span>` : ""}</div>
      <div class="detail-title">${esc(e.title)}</div></div></div>
    <div class="metric-grid mt">
      <div class="metric"><div class="k">① 언제</div><div class="v" style="font-size:var(--fs-md)">${dt(a.detected_at)}</div><div class="sub-ip">마지막 ${ago(a.last_seen)} · ${a.last_seen > a.detected_at ? dur(a.last_seen - a.detected_at) + " 동안" : "1회"}</div></div>
      <div class="metric"><div class="k">② 관련 IP</div><div class="v" style="font-size:var(--fs-md)">${ipHtml}</div><div class="sub-ip">${a.src && a.dst ? `→ ${esc(a.dst)}` : an.who ? esc(an.who).slice(0, 40) : ""}</div></div>
      <div class="metric"><div class="k">포트 · 프로토콜</div><div class="v" style="font-size:var(--fs-md)">${a.port ? `포트 ${a.port}` : "-"}</div><div class="sub-ip">${esc(an.protocol || a.protocol || "")}</div></div>
      <div class="metric"><div class="k">감지 횟수 · 대응</div><div class="v" style="font-size:var(--fs-md)">${num(a.count)}회</div><div class="sub-ip">${after ? after : (a.actions || []).length ? "조치 기록 있음" : "아직 조치 없음"}</div></div>
    </div>
    ${e.source_note ? `<div class="box box-sim">${esc(e.source_note)}</div>` : ""}
    <p class="summary-text">${esc(e.summary)}</p>
    <div class="section-h">③ 왜 이상하다고 판단했나요? <button class="btn btn-ghost btn-sm" id="ruleBtn" style="margin-left:auto">📐 규칙 설명</button></div>${gaugeHtml(a)}
    <div class="section-h">④ 정상 상황과 어떻게 다른가요?</div>${compareHtml(a) || `<div class="empty sm">비교할 측정값이 없어요</div>`}
    <div class="section-h">⑤ 예상되는 원인과 영향</div>
    <div class="analysis-grid">
      <div class="a-item"><div class="ak">무슨 일이에요?</div><div class="av">${esc(an.what)}</div></div>
      <div class="a-item"><div class="ak">판단 근거</div><div class="av">${esc(an.why)}</div></div>
      <div class="a-item"><div class="ak">어떤 장치가 관련됐나요?</div><div class="av">${esc(an.who)}</div></div>
      <div class="a-item"><div class="ak">어떤 통신 방식인가요?</div><div class="av">${esc(an.protocol)}</div></div>
      <div class="a-item" style="grid-column:1/-1"><div class="ak">어떤 영향이 있을 수 있나요?</div><div class="av">${esc(an.impact)}</div></div>
    </div>
    ${e.false_positive ? `<div class="callout mt"><b>💡 정상일 수도 있어요</b>${esc(e.false_positive)}</div>` : ""}
    ${(e.unknowns || []).length || e.method ? `<div class="callout mt"><b>🔎 탐지 방식과 한계</b>${e.method ? `탐지 방식: ${esc(e.method)}${e.evidence_basis ? " — " + esc(e.evidence_basis) : ""}<br>` : ""}${(e.unknowns || []).length ? "분석할 수 없었던 정보: " + e.unknowns.map(esc).join(" · ") : ""}${e.sni_independent ? "<br>이 판정은 SNI(도메인)를 쓰지 않아 ECH로 도메인이 숨겨져도 동작해요." : ""}</div>` : ""}
    <div class="section-h">⑥ 이렇게 해결해 보세요</div>${recs || `<div class="empty sm">추천 조치가 없어요</div>`}
    <div style="display:flex;gap:8px;margin-top:8px">${["active", "ended"].includes(a.status) ? `<button class="btn btn-secondary btn-sm" id="dismissBtn">정상 통신이에요</button>` : ""}</div>
    <div class="section-h">⑦ 진행 타임라인 · 발생 → 탐지 → 조치 → 검증</div>${timelineHtml(a)}
    ${hist ? `<div class="section-h">조치 기록 상세</div>${hist}` : ""}
    <details class="more" ${S.expert ? "open" : ""}><summary>전문가용 원본 정보 (탐지 유형 ${esc(a.type)})</summary>
      <div class="code">${esc(e.technical || "")}\n\n${esc(JSON.stringify(evid, null, 2))}</div></details>`;
  $$("#issueDetail [data-rec]").forEach((b) => b.onclick = () => { const r = e.recommendations[+b.dataset.rec]; openAction(r.action, r.params, a.id); });
  const db = $("#dismissBtn"); if (db) db.onclick = () => dismissIssue(a);
  const rb = $("#ruleBtn"); if (rb) rb.onclick = () => hooks.openRule && hooks.openRule(a.type);
  bindHistButtons($("#issueDetail"));
}
function histHtml(x) {
  const title = (S.catalog && S.catalog.actions[x.action] || {}).title || x.action;
  const st = x.rolled_back_at ? "rolled_back" : x.status;
  const cls = { success: "s-good", simulated: "s-test", failed: "s-danger", rolled_back: "s-info", cancelled: "s-info" }[st] || "s-info";
  const res = x.result || {}, v = x.verification || {}, rb = x.rollback_result || {};
  const canVerify = x.action === "block_ip" && x.status === "success" && !x.rolled_back_at && !x.simulated;
  const canRollback = x.rollback_info && !x.rolled_back_at && ["success", "simulated"].includes(x.status);
  return `<div class="hist"><div class="hist-head"><div><b>${esc(title)}</b> <span class="sev-badge ${cls}">${esc(ACT_STATUS[st] || st)}</span>
      ${x.trigger === "auto" ? `<span class="sev-badge s-warning">자동</span>` : ""}</div><span class="sub-ip">${dt(x.created_at)}</span></div>
    <div class="hist-msg">${esc(res.message || "")}</div>${resultDetail(x.action, res)}
    ${v.message && x.action === "block_ip" ? `<div class="hist-msg">🔎 ${esc(v.message)}</div>` : ""}
    ${x.rolled_back_at ? `<div class="hist-msg">↩️ ${esc(rb.message || "되돌렸어요")} (${dt(x.rolled_back_at)})</div>` : ""}
    ${x.expires_at && !x.rolled_back_at ? `<div class="hist-msg sub-ip">자동 해제 예정: ${dt(x.expires_at)}</div>` : ""}
    ${canVerify || canRollback ? `<div class="hist-actions">${canVerify ? `<button class="btn btn-secondary btn-sm" data-verify="${x.id}">효과 검증</button>` : ""}
      ${canRollback ? `<button class="btn btn-secondary btn-sm" data-rollback="${x.id}">↩️ 되돌리기</button>` : ""}</div>` : ""}</div>`;
}
function bindHistButtons(root) {
  $$("[data-verify]", root).forEach((b) => b.onclick = async () => {
    try { const v = await api(`/api/actions/${b.dataset.verify}/verify`, { method: "POST", body: {} }); toast(v.message); refreshAfterAction(); } catch (e) { toast(e.message, true); }
  });
  $$("[data-rollback]", root).forEach((b) => b.onclick = () => confirmRollback(+b.dataset.rollback));
}
export function resultDetail(action, r) {
  if (!r) return "";
  if (r.steps) return `<ul class="steps">${r.steps.map((s) => `<li><span class="${s.ok ? "ok" : "bad"}">${s.ok ? "✓" : "✕"}</span><b>${esc(s.label)}</b><span class="sub-ip">${esc(s.detail)}</span></li>`).join("")}</ul>`;
  if (r.dns || r.dns_after) {
    const dns = r.dns || r.dns_after;
    return `<ul class="steps">${dns.results.map((x) => `<li><span class="${x.ok ? "ok" : "bad"}">${x.ok ? "✓" : "✕"}</span><b>${esc(x.domain)}</b><span class="sub-ip">${x.ok ? `${x.ms}ms · ${esc(x.addresses.slice(0, 2).join(", "))}` : esc(x.error)}</span></li>`).join("")}</ul>`;
  }
  if (r.processes) {
    if (!r.processes.length) return "";
    return `<table class="mini-table"><tr><th>프로그램</th><th>PID</th><th>연결</th><th>상대</th></tr>${r.processes.slice(0, 12).map((p) =>
      `<tr><td><b>${esc(p.process)}</b></td><td class="mono">${p.pid ?? "-"}</td><td>${p.connections}</td><td class="mono">${esc((p.remotes || []).slice(0, 3).join(", "))}</td></tr>`).join("")}</table>`;
  }
  if (r.summary && r.services) {
    return `<table class="mini-table"><tr><th>서비스</th><th>패킷</th></tr>${r.services.map((s) => `<tr><td>${esc(s.proto)} ${esc(s.service)}</td><td>${num(s.packets)}</td></tr>`).join("")}</table>
      ${r.domain ? `<div class="hist-msg sub-ip">도메인: ${esc(r.domain)}</div>` : ""}<div class="hist-msg sub-ip">처음 ${dt(r.summary.first_ts)} · 마지막 ${dt(r.summary.last_ts)}</div>`;
  }
  if (r.commands) return `<div class="code">${esc(r.commands.filter((c) => !c.startsWith("echo")).join("\n"))}</div>`;
  if (r.output && S.expert) return `<div class="code">${esc((r.output.stdout || "") + (r.output.stderr || ""))}</div>`;
  return "";
}
function dismissIssue(a) {
  const ip = a.src || a.dst;
  modal(`<h3>정상 통신으로 표시할까요?</h3><p class="card-sub">직접 실행한 프로그램이나 알고 있는 장치라면 정상으로 표시해 주세요. 이 기록은 ‘정상 처리’ 목록으로 옮겨져요.</p>
    ${ip ? `<label class="check"><input type="checkbox" id="wlChk"> 앞으로 <b>${esc(ip)}</b> 는 탐지하지 않기 (화이트리스트 추가)</label>` : ""}
    <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">취소</button><button class="btn btn-primary" id="dmOk">정상으로 표시</button></div>`);
  $("#dmOk").onclick = async () => {
    try {
      const r = await api(`/api/anomalies/${a.id}/dismiss`, { method: "POST", body: { whitelist: !!($("#wlChk") && $("#wlChk").checked) } });
      closeModal(); toast(r.whitelisted ? `${r.whitelisted} 를 화이트리스트에 추가했어요` : "정상 처리했어요"); loadIssues(); selectIssue(a.id, true);
    } catch (e) { toast(e.message, true); }
  };
}

/* ── 조치 실행 ── */
export async function openAction(action, params, anomalyId) {
  modal(loadingHtml("조치 내용을 확인하는 중…"));
  let pv;
  try { pv = await api("/api/actions/preview", { method: "POST", body: { action, params, anomaly_id: anomalyId } }); }
  catch (e) { modal(`<h3>확인할 수 없어요</h3><div class="box box-red">${esc(e.message)}</div><div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button></div>`); return; }
  const sp = pv.spec;
  const target = pv.params.ip ? ` · ${pv.params.ip}` : pv.params.port ? ` · 포트 ${pv.params.port}` : "";
  const needConsent = sp.changes_system && !pv.blocked_reason;
  let html = `<h3>${esc(sp.title)}${esc(target)}</h3>
    <div>${sp.changes_system ? `<span class="tag tag-change" style="margin:0">시스템 설정 변경</span>` : `<span class="tag tag-safe" style="margin:0">설정 변경 없음</span>`}
      ${sp.requires_admin ? `<span class="tag tag-admin">관리자 권한 필요</span>` : ""}${sp.reversible ? `<span class="tag tag-safe">되돌리기 가능</span>` : ""}${pv.simulated ? `<span class="tag b-sim">시뮬레이션</span>` : ""}</div>
    <div class="box box-gray"><b>무엇을 하나요?</b>${esc(sp.description)}</div>
    <div class="box ${sp.risk === "high" ? "box-warn" : "box-gray"}"><b>예상되는 영향(부작용)</b>${esc(sp.side_effects)}</div>`;
  for (const w of pv.warnings || []) html += `<div class="box box-warn">⚠️ ${esc(w)}</div>`;
  if (pv.blocked_reason) html += `<div class="box box-red"><b>이 조치는 실행할 수 없어요</b>${esc(pv.blocked_reason)}</div>`;
  if (pv.simulated) html += `<div class="box box-sim">테스트 데이터에서 나온 징후라서 실제 시스템은 바꾸지 않고, 실행될 명령만 보여드려요.</div>`;
  if (pv.needs_admin && !pv.blocked_reason) {
    html += `<div class="box box-warn"><b>관리자 권한이 필요해요</b>NetCare가 관리자 권한 없이 실행 중이에요. ${pv.can_elevate ? "아래에서 ‘관리자 암호로 실행’을 선택하면 macOS 암호 입력 창이 떠요. 또는" : ""} 아래 명령을 터미널에서 직접 실행하거나, NetCare를 관리자 권한(sudo)으로 다시 실행해 주세요.
      <div class="code">${esc(pv.manual_command || "")}</div></div>`;
  }
  if (pv.commands && pv.commands.length && !pv.needs_admin) {
    html += `<details class="more" ${S.expert ? "open" : ""}><summary>실행될 명령 보기</summary><div class="code">${esc(pv.commands.filter((c) => !c.startsWith("echo")).join("\n"))}</div></details>`;
  }
  if (needConsent) html += `<label class="check"><input type="checkbox" id="acChk"> 위의 내용과 부작용을 이해했고, 실행에 동의해요.</label>`;
  const canRun = !pv.blocked_reason && (!pv.needs_admin || pv.can_elevate);
  html += `<div id="acResult"></div><div class="modal-actions" id="acBtns"><button class="btn btn-secondary" onclick="App.closeModal()">${canRun ? "취소" : "닫기"}</button>
    ${canRun ? `<button class="btn ${sp.risk === "high" && !pv.simulated ? "btn-danger" : "btn-primary"}" id="acRun" ${needConsent ? "disabled" : ""}>${pv.needs_admin ? "관리자 암호로 실행" : pv.simulated ? "시뮬레이션 실행" : "실행하기"}</button>` : ""}</div>`;
  modal(html);
  const chk = $("#acChk"), run = $("#acRun");
  if (chk && run) chk.onchange = () => run.disabled = !chk.checked;
  if (run) run.onclick = async () => {
    run.disabled = true; run.textContent = pv.needs_admin ? "암호 입력 창을 확인하세요…" : "실행 중…";
    try {
      const rec = await api("/api/actions/execute", { method: "POST", body: { action, params: pv.params, anomaly_id: anomalyId,
        confirm: needConsent ? chk.checked : false, acknowledge_risk: needConsent ? chk.checked : false, elevate: !!pv.needs_admin } });
      const res = rec.result || {};
      const ok = ["success", "simulated"].includes(rec.status);
      $("#acResult").innerHTML = `<div class="box ${ok ? "box-green" : "box-red"}"><b>${ok ? "완료했어요" : rec.status === "cancelled" ? "취소됐어요" : "실패했어요"}</b>${esc(res.message || "")}${resultDetail(action, res)}</div>`;
      $("#acBtns").innerHTML = `<button class="btn btn-primary" onclick="App.closeModal()">확인</button>`;
      refreshAfterAction();
    } catch (e) {
      $("#acResult").innerHTML = `<div class="box box-red"><b>실행하지 못했어요</b>${esc(e.message)}${e.manual_command ? `<div class="code">${esc(e.manual_command)}</div>` : ""}</div>`;
      run.disabled = false; run.textContent = "다시 시도";
    }
  };
}
function confirmRollback(id) {
  modal(`<h3>조치를 되돌릴까요?</h3><p class="card-sub">NetCare가 추가한 방화벽 규칙을 지우고, 실행 전 상태(pf 활성 여부 등)로 돌려놓아요.</p>
    <div id="rbResult"></div><div class="modal-actions" id="rbBtns"><button class="btn btn-secondary" onclick="App.closeModal()">취소</button><button class="btn btn-primary" id="rbOk">되돌리기</button></div>`);
  const doIt = async (elevate) => {
    try {
      const r = await api(`/api/actions/${id}/rollback`, { method: "POST", body: { confirm: true, elevate } });
      $("#rbResult").innerHTML = `<div class="box box-green">${esc((r.rollback_result || {}).message || "되돌렸어요")}</div>`;
      $("#rbBtns").innerHTML = `<button class="btn btn-primary" onclick="App.closeModal()">확인</button>`;
      refreshAfterAction();
    } catch (e) {
      $("#rbResult").innerHTML = `<div class="box box-red"><b>${esc(e.message)}</b>${e.manual_command ? `<div class="code">${esc(e.manual_command)}</div>` : ""}</div>`;
      if (e.code === "needs_admin" && e.can_elevate) { $("#rbOk").textContent = "관리자 암호로 되돌리기"; $("#rbOk").onclick = () => doIt(true); }
    }
  };
  $("#rbOk").onclick = () => doIt(false);
}
function refreshAfterAction() { if (S.is.sel) selectIssue(S.is.sel, true); loadIssues(); }

export function bindIssues() {
  $$("#isChips .chip").forEach((c) => c.onclick = () => { $$("#isChips .chip").forEach((x) => x.classList.toggle("on", x === c)); S.is.filter = c.dataset.s; renderIssueList(); });
}
