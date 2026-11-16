/* 탐지 규칙 카탈로그: 조건·임계값·근거·위험 수준·오탐 가능성·적용 환경·한계 */
import { $, $$, api, esc, toast, hooks } from "./core.js";
import { modal } from "./ui.js";

let cache = null;
async function load() { if (!cache) cache = (await api("/api/rules")).rules; return cache; }
export function invalidateRules() { cache = null; }

export async function openRules(selected = null) {
  let rules;
  try { rules = await load(); } catch (e) { toast(e.message, true); return; }
  const cats = [...new Set(rules.map((r) => r.category_label))];
  modal(`<div class="row" style="justify-content:space-between"><h3 style="margin:0">탐지 규칙 ${rules.length}종</h3><span class="sub-ip">임계값은 현재 설정값</span></div>
    <p class="card-sub">규칙을 누르면 조건·근거·오탐 가능성·한계를 볼 수 있어요. 패킷만으로 확정할 수 없는 규칙은 '의심'으로 표시해요.</p>
    <div class="grid g-2" style="gap:var(--sp-4)">
      <div style="max-height:62vh;overflow:auto">${cats.map((c) => `<div class="sr-group"><h5>${esc(c)}</h5>${rules.filter((r) => r.category_label === c).map((r) =>
        `<div class="sr-item ${r.type === selected ? "on" : ""}" data-rule="${esc(r.type)}"><span class="sr-t">${esc(r.label)}</span><span class="sr-s">${r.certainty === "suspected" ? `<span class="sev-badge b-warn">의심</span>` : r.basis === "probe" ? `<span class="sev-badge b-info">실측</span>` : ""}</span></div>`).join("")}</div>`).join("")}</div>
      <div id="ruleDetail" style="max-height:62vh;overflow:auto">${selected ? "" : `<div class="empty"><div class="empty-icon">📐</div><div class="empty-title">왼쪽에서 규칙을 선택하세요</div></div>`}</div>
    </div>
    <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button></div>`, "xl");
  $$("#modalCard [data-rule]").forEach((el) => el.onclick = () => { $$("#modalCard [data-rule]").forEach((x) => x.classList.toggle("on", x === el)); renderRule(rules.find((r) => r.type === el.dataset.rule)); });
  if (selected) { const r = rules.find((x) => x.type === selected); if (r) renderRule(r); }
}
function renderRule(r) {
  const li = (arr) => arr && arr.length ? `<ul style="margin:4px 0 0 18px;padding:0;line-height:1.6">${arr.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : `<div class="sub-ip">-</div>`;
  $("#ruleDetail").innerHTML = `<div class="row wrap" style="margin-bottom:6px"><span class="sev-badge b-primary">${esc(r.category_label)}</span><span class="sev-badge b-neutral">${esc(r.basis_label)}</span>
      <span class="sev-badge ${r.certainty === "suspected" ? "b-warn" : r.certainty === "likely" ? "b-info" : "s-good"}">${esc(r.certainty_label)}</span><span class="mono sub-ip">${esc(r.type)}</span></div>
    <h3 style="margin:0 0 8px">${esc(r.label)}</h3>
    <div class="inset"><div class="sub-ip" style="font-weight:600;margin-bottom:4px">탐지 조건</div><div style="line-height:1.6">${esc(r.condition)}</div>
      ${r.thresholds.length ? `<div class="row wrap" style="margin-top:8px">${r.thresholds.map((t) => `<span class="chip-mini mono">${esc(t.key)} = ${esc(String(t.value))}</span>`).join("")}</div>` : ""}</div>
    <div class="kv mt" style="grid-template-columns:110px 1fr">
      <div class="k">위험 수준</div><div class="v">${esc(r.severity)}</div>
      <div class="k">탐지 근거</div><div class="v" style="font-weight:500">${esc(r.evidence)}</div>
      <div class="k">오탐 가능성</div><div class="v" style="font-weight:500">${li(r.false_positives)}</div>
      <div class="k">적용 환경</div><div class="v" style="font-weight:500">${li(r.environments)}</div>
      <div class="k">한계</div><div class="v" style="font-weight:500">${li(r.limits)}</div></div>
    ${r.thresholds.length ? `<div class="sub-ip" style="margin-top:10px">임계값은 ⚙ 설정 → 탐지 기준에서 바꿀 수 있어요.</div>` : ""}`;
}
export function bindRules() { hooks.openRule = (t) => openRules(t); }
