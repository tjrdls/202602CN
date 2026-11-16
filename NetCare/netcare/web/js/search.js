/* 전역 검색 (Cmd/Ctrl+K): IP·도메인·이상 징후·포트·탐지 규칙 */
import { $, $$, api, esc, num, ago, hooks, debounce, STATUS_KO } from "./core.js";
import { modal, closeModal, sevPill, srcPill } from "./ui.js";
import { openIpDetail } from "./ipdetail.js";

let lastQ = "";
export function openSearch(initial = "") {
  modal(`<div class="search-modal"><input class="input" id="gsInput" placeholder="IP, 도메인, 포트, 이상 징후 검색…" value="${esc(initial)}" autocomplete="off">
    <div id="gsResults"><div class="empty sm">예: 192.168, github, 443, 스푸핑</div></div>
    <div class="sub-ip" style="margin-top:10px;display:flex;gap:10px"><span><span class="kbd">↑</span><span class="kbd">↓</span> 이동</span><span><span class="kbd">Enter</span> 열기</span><span><span class="kbd">Esc</span> 닫기</span></div></div>`);
  const inp = $("#gsInput");
  inp.focus(); inp.select();
  inp.oninput = debounce(() => runSearch(inp.value.trim()), 220);
  inp.onkeydown = (e) => {
    const items = $$("#gsResults .sr-item"); if (!items.length) return;
    let i = items.findIndex((x) => x.classList.contains("on"));
    if (e.key === "ArrowDown") { e.preventDefault(); i = Math.min(items.length - 1, i + 1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); i = Math.max(0, i - 1); }
    else if (e.key === "Enter") { e.preventDefault(); (items[i] || items[0]).click(); return; }
    else return;
    items.forEach((x, k) => x.classList.toggle("on", k === i));
    items[i].scrollIntoView({ block: "nearest" });
  };
  if (initial) runSearch(initial);
}
async function runSearch(q) {
  lastQ = q;
  const box = $("#gsResults"); if (!box) return;
  if (!q) { box.innerHTML = `<div class="empty sm">예: 192.168, github, 443, 스푸핑</div>`; return; }
  let r;
  try { r = await api("/api/search?q=" + encodeURIComponent(q)); } catch (e) { box.innerHTML = `<div class="error-box">${esc(e.message)}</div>`; return; }
  if (lastQ !== q) return;
  const groups = [];
  if (r.ips.length) groups.push(["장치(IP)", r.ips.map((x) => `<div class="sr-item" data-ip="${esc(x.ip)}"><span class="sr-ic">💻</span><span class="sr-t">${esc(x.label)} <span class="mono" style="color:var(--text-3)">${esc(x.ip)}</span></span><span class="sr-s">${num(x.packets)}개 패킷</span></div>`)]);
  if (r.names.length) groups.push(["도메인", r.names.map((x) => `<div class="sr-item" data-ip="${esc(x.ip)}"><span class="sr-ic">🌐</span><span class="sr-t">${esc(x.name)}</span><span class="sr-s mono">${esc(x.ip)}</span></div>`)]);
  if (r.ports.length) groups.push(["포트", r.ports.map((x) => `<div class="sr-item" data-port="${x.port}"><span class="sr-ic">🔌</span><span class="sr-t">포트 ${x.port}의 패킷 보기</span><span class="sr-s">${esc(x.label)}</span></div>`)]);
  if (r.anomalies.length) groups.push(["이상 징후", r.anomalies.map((a) => `<div class="sr-item" data-anom="${a.id}"><span class="sr-ic">⚠️</span><span class="sr-t">${esc(a.title)} ${sevPill(a.severity)} ${srcPill(a.source)}</span><span class="sr-s">${esc(STATUS_KO[a.status] || a.status)} · ${ago(a.last_seen)}</span></div>`)]);
  if (r.rules.length) groups.push(["탐지 규칙", r.rules.map((x) => `<div class="sr-item" data-rule="${esc(x.type)}"><span class="sr-ic">📐</span><span class="sr-t">${esc(x.label)}</span><span class="sr-s">규칙 설명 보기</span></div>`)]);
  box.innerHTML = groups.length ? groups.map(([h, items]) => `<div class="sr-group"><h5>${h}</h5>${items.join("")}</div>`).join("") : `<div class="empty sm">"${esc(q)}"에 해당하는 기록이 없어요</div>`;
  const first = $("#gsResults .sr-item"); if (first) first.classList.add("on");
  $$("#gsResults [data-ip]").forEach((el) => el.onclick = () => openIpDetail(el.dataset.ip));
  $$("#gsResults [data-anom]").forEach((el) => el.onclick = () => { closeModal(); hooks.go("issues/" + el.dataset.anom); });
  $$("#gsResults [data-port]").forEach((el) => el.onclick = () => { closeModal(); hooks.go("packets"); hooks.setPacketFilter && hooks.setPacketFilter({ port: +el.dataset.port }); });
  $$("#gsResults [data-rule]").forEach((el) => el.onclick = () => { closeModal(); hooks.openRule && hooks.openRule(el.dataset.rule); });
}
