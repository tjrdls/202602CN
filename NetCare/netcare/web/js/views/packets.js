/* 패킷 분석: 목록·필터·정렬·페이지·상세(넓은 화면은 오른쪽 패널, 좁은 화면은 드로어) */
import { S, $, $$, api, esc, num, bytes, tm, dt, toast, hooks, debounce } from "../core.js";
import { srcPill, openDrawer, closeDrawer, loadingHtml, errorHtml } from "../ui.js";
import { ipLink } from "../ipdetail.js";
import { bindEncrypted, loadEncrypted, encDetailHtml } from "./encrypted.js";

const PAGE = 100;
/* S.pk: rows, lastId, proto, q, ip, port, paused, sessionId, newIds, sort, order, mode(live|paged), page, total */
Object.assign(S.pk, { ip: "", port: "", tag: "", tagLabel: "", sort: "id", order: "desc", mode: "live", page: 1, total: null });

const COLS_EASY = [["ts", "시간", true], ["dir", "방향", false], ["src", "보내는 장치", true], ["dst", "받는 장치", true], ["proto", "종류", true], ["ports", "포트", false], ["length", "크기", true, "num"], ["info", "설명", false]];
const COLS_EXPERT = [["id", "No.", true], ["ts", "Time", true], ["src", "Source", true], ["dst", "Destination", true], ["proto", "Protocol", true], ["sport", "SPort", true, "num"], ["dport", "DPort", true, "num"], ["flags", "Flags", false], ["ttl", "TTL", false, "num"], ["length", "Len", true, "num"], ["info", "Info", false]];

export function renderPkHead() {
  const cols = S.expert ? COLS_EXPERT : COLS_EASY;
  $("#pkHead").innerHTML = `<tr>${cols.map(([k, label, sortable, cls]) => {
    const on = S.pk.sort === k && S.pk.mode === "paged";
    return `<th class="${sortable ? "sortable" : ""} ${on ? S.pk.order : ""} ${cls || ""}" ${sortable ? `data-sort="${k}"` : ""}>${label}</th>`;
  }).join("")}</tr>`;
  $$("#pkHead th[data-sort]").forEach((th) => th.onclick = () => setSort(th.dataset.sort));
}
const dirMark = (d) => d === "up" ? `<span class="dir dir-up">↑ 보냄</span>` : d === "down" ? `<span class="dir dir-down">↓ 받음</span>` : d === "local" ? `<span class="dir">내부</span>` : `<span class="dir" style="color:var(--text-3)">외부↔외부</span>`;
function pkRow(r) {
  const cls = (S.pk.newIds.has(r.id) ? "new" : "") + (S.lastPacket && S.lastPacket.packet && S.lastPacket.packet.id === r.id ? " sel" : "");
  const ports = r.sport != null ? `${r.sport} → ${r.dport}` : "-";
  if (S.expert) {
    return `<tr data-id="${r.id}" class="${cls}"><td class="mono">${r.id}</td><td class="mono">${esc(tm(r.ts))}.${String(Math.floor((r.ts % 1) * 1000)).padStart(3, "0")}</td>
      <td class="mono">${esc(r.src || r.src_mac || "-")}</td><td class="mono">${esc(r.dst || r.dst_mac || "-")}</td><td><span class="proto p-${esc(r.proto)}">${esc(r.proto)}</span></td>
      <td class="mono num">${r.sport ?? ""}</td><td class="mono num">${r.dport ?? ""}</td><td class="mono">${esc(r.flags || "")}</td><td class="mono num">${r.ttl ?? ""}</td><td class="mono num">${r.length}</td><td class="mono" title="${esc(r.info)}">${esc(r.info)}</td></tr>`;
  }
  return `<tr data-id="${r.id}" class="${cls}"><td class="mono">${esc(tm(r.ts))}</td><td>${dirMark(r.direction)}</td>
    <td title="${esc(r.src)}">${esc(r.src_label)}</td><td title="${esc(r.dst)}">${esc(r.dst_label)}</td>
    <td><span class="proto p-${esc(r.proto)}">${esc(r.service || r.proto)}</span></td><td class="mono">${esc(ports)}</td><td class="num">${bytes(r.length)}</td>
    <td title="${esc(r.friendly)}">${esc(r.friendly)}</td></tr>`;
}
export function renderPackets() {
  const rows = S.pk.rows, P = S.pk;
  $("#pkEmpty").classList.toggle("hidden", rows.length > 0);
  $("#pkBody").innerHTML = rows.map(pkRow).join("");
  const filt = [P.proto && P.proto, P.q && `"${P.q}"`, P.ip && `IP ${P.ip}`, P.port && `포트 ${P.port}`, P.tag && P.tagLabel].filter(Boolean);
  $("#pkTagChip").classList.toggle("hidden", !P.tag);
  if (P.tag) $("#pkTagChip").textContent = `🔐 ${P.tagLabel} ✕`;
  if (P.mode === "paged") {
    const pages = Math.max(1, Math.ceil((P.total || 0) / PAGE));
    $("#pkInfo").textContent = rows.length ? `전체 ${num(P.total)}개 중 ${num((P.page - 1) * PAGE + 1)}~${num((P.page - 1) * PAGE + rows.length)} · 정렬 ${P.sort} ${P.order === "asc" ? "오름차순" : "내림차순"}${filt.length ? " · 필터 " + filt.join(", ") : ""}` : "";
    $("#pkPager").classList.remove("hidden"); $("#pkMore").classList.add("hidden"); $("#pkModeNote").classList.remove("hidden");
    $("#pkPager").innerHTML = `<button class="btn btn-ghost btn-sm" data-pg="1" ${P.page <= 1 ? "disabled" : ""}>«</button><button class="btn btn-ghost btn-sm" data-pg="${P.page - 1}" ${P.page <= 1 ? "disabled" : ""}>‹</button>
      <span class="sub-ip">${P.page} / ${pages}</span><button class="btn btn-ghost btn-sm" data-pg="${P.page + 1}" ${P.page >= pages ? "disabled" : ""}>›</button><button class="btn btn-ghost btn-sm" data-pg="${pages}" ${P.page >= pages ? "disabled" : ""}>»</button>`;
    $$("#pkPager [data-pg]").forEach((b) => b.onclick = () => { P.page = Math.max(1, +b.dataset.pg); loadPaged(); });
  } else {
    $("#pkInfo").textContent = rows.length ? `${num(rows.length)}개 표시 중${P.paused ? " · 일시정지됨" : " · 실시간"}${filt.length ? " · 필터 " + filt.join(", ") : ""}` : "";
    $("#pkPager").classList.add("hidden"); $("#pkMore").classList.remove("hidden"); $("#pkModeNote").classList.add("hidden");
  }
  S.pk.newIds.clear();
}
function filterParams(p) {
  const P = S.pk;
  if (P.proto) p.set("proto", P.proto);
  if (P.q) p.set("q", P.q);
  if (P.ip) p.set("ip", P.ip);
  if (P.port !== "" && P.port != null) p.set("port", P.port);
  if (P.tag) p.set("tag", P.tag);
  return p;
}
export async function loadPackets(reset = false) {
  loadEncrypted(reset);
  if (S.pk.mode === "paged") { if (reset) { S.pk.page = 1; await loadPaged(); } return; }
  const sid = S.status && S.status.session ? S.status.session.id : null;
  if (reset || sid !== S.pk.sessionId) { S.pk.rows = []; S.pk.lastId = 0; S.pk.sessionId = sid; }
  const p = filterParams(new URLSearchParams({ limit: reset || !S.pk.lastId ? 300 : 500 }));
  if (S.pk.lastId) p.set("after_id", S.pk.lastId);
  try {
    const d = await api("/api/packets?" + p);
    if (d.packets.length) {
      if (S.pk.lastId) d.packets.forEach((r) => S.pk.newIds.add(r.id));
      S.pk.rows = d.packets.concat(S.pk.rows).slice(0, 1000);
      S.pk.lastId = Math.max(S.pk.lastId, d.packets[0].id);
    }
    renderPackets();
  } catch (e) { if (e.offline) hooks.showOffline(); }
}
async function loadPaged() {
  const P = S.pk;
  const p = filterParams(new URLSearchParams({ limit: PAGE, offset: (P.page - 1) * PAGE, sort: P.sort, order: P.order, with_total: "true" }));
  try {
    const d = await api("/api/packets?" + p);
    P.rows = d.packets; P.total = d.total; P.sessionId = d.session_id;
    renderPackets();
  } catch (e) { if (e.offline) hooks.showOffline(); else toast(e.message, true); }
}
function setSort(k) {
  const P = S.pk;
  if (P.mode === "paged" && P.sort === k) P.order = P.order === "asc" ? "desc" : "asc";
  else { P.sort = k; P.order = k === "ts" || k === "id" || k === "length" ? "desc" : "asc"; }
  P.mode = "paged"; P.page = 1;
  renderPkHead(); loadPaged();
}
function backToLive() { Object.assign(S.pk, { mode: "live", sort: "id", order: "desc", page: 1, total: null }); renderPkHead(); loadPackets(true); }
export function setPacketFilter(f) {
  if (f.ip !== undefined) { S.pk.ip = f.ip || ""; $("#pkIp").value = S.pk.ip; }
  if (f.port !== undefined) { S.pk.port = f.port === null || f.port === "" ? "" : String(f.port); $("#pkPort").value = S.pk.port; }
  loadPackets(true);
}
export async function loadOlderPackets() {
  const oldest = S.pk.rows.length ? S.pk.rows[S.pk.rows.length - 1].id : null;
  if (!oldest) return;
  const p = filterParams(new URLSearchParams({ limit: 300, before_id: oldest }));
  const d = await api("/api/packets?" + p);
  S.pk.rows = S.pk.rows.concat(d.packets).slice(0, 3000);
  renderPackets();
  if (!d.packets.length) toast("더 이전 패킷이 없어요");
}

/* ── 상세 ── */
const wide = () => window.innerWidth > 1100 && S.view === "packets";
function showDetail(html) {
  if (wide()) {
    const panel = $("#pkDetail"); panel.innerHTML = html; panel.classList.remove("hidden"); $("#pkLayout").classList.add("with-detail");
    closeDrawer();
  } else openDrawer(html);
}
export function closePacketDetail() {
  $("#pkDetail").classList.add("hidden"); $("#pkLayout").classList.remove("with-detail"); closeDrawer(); S.lastPacket = null;
  $$("#pkBody tr.sel").forEach((tr) => tr.classList.remove("sel"));
}
export async function openPacket(id, lab = false) {
  showDetail(loadingHtml());
  let d;
  try { d = await api(lab ? `/api/lab/packets/${id}` : `/api/packets/${id}`); } catch (e) { showDetail(errorHtml(e.message)); return; }
  S.lastPacket = d;
  renderPacketDrawer();
  $$("#pkBody tr").forEach((tr) => tr.classList.toggle("sel", +tr.dataset.id === id));
}
export function renderPacketDrawer() {
  const d = S.lastPacket; if (!d) return;
  const p = d.packet, t = d.tree;
  const dirTxt = { up: "내 컴퓨터에서 보낸 데이터", down: "내 컴퓨터가 받은 데이터", local: "내 컴퓨터 내부 통신", other: "다른 장치 사이의 통신" }[p.direction] || "";
  const layers = (t.layers || []).map((l, i) => `<details class="layer" ${i < 4 ? "open" : ""}><summary><span>${esc(S.expert ? l.name : l.title)}</span>
      <span class="meta">${S.expert ? `offset ${l.offset} · ${l.length}B` : `${l.length}바이트`}</span></summary>
      <div class="fields">${l.note ? `<div class="note">🔒 ${esc(l.note)}</div>` : ""}${l.fields.map((f) => `<div class="field"><div class="fl">${esc(f.label)}${S.expert && f.label !== f.name ? `<span class="tech">${esc(f.name)}</span>` : ""}</div>
        <div class="fv">${esc(f.value)}</div>${f.desc && !S.expert ? `<div class="fd">${esc(f.desc)}</div>` : ""}</div>`).join("")}</div></details>`).join("");
  const hex = (t.hex || []).map((r) => `<div><span class="o">${r.offset}</span>${esc(r.hex.padEnd(47, " "))}<span class="a">${esc(r.ascii)}</span></div>`).join("");
  const sim = p.source === "sim";
  showDetail(`<div class="drawer-head"><h3>패킷 #${p.id}</h3><button class="icon-btn" onclick="App.closePacketDetail()" aria-label="닫기">✕</button></div>
    <div class="${wide() ? "" : "card tight"}">
      ${srcPill(p.source)}
      <div style="font-weight:var(--fw-black);font-size:var(--fs-lg);margin:6px 0 4px">${esc(p.friendly)}</div>
      <div class="card-sub" style="margin:0">${esc(dirTxt)} · ${dt(p.ts)}</div>
      <div class="flow"><div class="node"><div class="t">보내는 장치</div><div class="n" title="${esc(p.src_label)}">${esc(p.src_label)}</div><div class="ip">${sim ? esc(p.src || p.src_mac || "") : ipLink(p.src || p.src_mac || "")}${p.sport != null ? ":" + p.sport : ""}</div></div>
        <div class="mid">→</div>
        <div class="node"><div class="t">받는 장치</div><div class="n" title="${esc(p.dst_label)}">${esc(p.dst_label)}</div><div class="ip">${sim ? esc(p.dst || p.dst_mac || "") : ipLink(p.dst || p.dst_mac || "")}${p.dport != null ? ":" + p.dport : ""}</div></div></div>
      <div class="kv"><div class="k">통신 종류</div><div class="v">${esc(p.service_desc || p.protocol_desc || p.proto)}</div>
        <div class="k">전송 방식</div><div class="v">${esc(p.protocol_desc || p.proto)}</div>
        <div class="k">크기</div><div class="v">${num(p.length)} 바이트${p.truncated ? " (앞부분만 저장됨)" : ""}</div>
        ${p.flags ? `<div class="k">TCP 플래그</div><div class="v mono">${esc(p.flags)}</div>` : ""}
        ${p.src_domain || p.dst_domain ? `<div class="k">도메인</div><div class="v">${esc(p.src_domain || p.dst_domain)} <span class="sub-ip">(이 컴퓨터가 조회한 DNS 응답 기준)</span></div>` : ""}
        ${p.ttl != null ? `<div class="k">TTL</div><div class="v">${p.ttl} <span class="sub-ip">(라우터를 지날 때마다 1씩 줄어요)</span></div>` : ""}</div>
    </div>
    <div class="section-h">계층 구조 ${S.expert ? "(Protocol tree)" : "· 데이터가 어떻게 포장되어 있는지"}</div>
    ${!S.expert ? `<div class="card-sub">바깥쪽(이더넷)부터 안쪽(응용 데이터)까지, 편지 봉투처럼 겹겹이 싸여 전달돼요.</div>` : ""}
    ${layers || `<div class="empty sm">${esc(t.note || "헤더 정보가 없어요")}</div>`}
    ${encDetailHtml(d.encrypted)}
    <details class="more" ${S.expert ? "open" : ""}><summary>원본 바이트(헥사 덤프) 보기</summary><div class="hex" style="margin-top:8px">${hex || "원본 없음"}</div></details>`);
}

export function bindPackets() {
  $$("#pkChips .chip").forEach((c) => c.onclick = () => { $$("#pkChips .chip").forEach((x) => x.classList.toggle("on", x === c)); S.pk.proto = c.dataset.p; loadPackets(true); });
  $("#pkSearch").oninput = debounce((e) => { S.pk.q = e.target.value.trim(); loadPackets(true); }, 300);
  $("#pkIp").oninput = debounce((e) => { S.pk.ip = e.target.value.trim(); loadPackets(true); }, 300);
  $("#pkPort").oninput = debounce((e) => { S.pk.port = e.target.value.trim(); loadPackets(true); }, 300);
  bindEncrypted((f) => {
    const same = S.pk.tag === f.tag && f.tag;
    S.pk.tag = same ? "" : (f.tag || ""); S.pk.tagLabel = same ? "" : f.label;
    if (!f.tag && f.proto) { S.pk.proto = f.proto; $$("#pkChips .chip").forEach((x) => x.classList.toggle("on", x.dataset.p === f.proto)); }
    loadPackets(true);
  });
  $("#pkTagChip").onclick = () => { S.pk.tag = ""; S.pk.tagLabel = ""; loadPackets(true); };
  $("#pkClear").onclick = () => { S.pk.q = ""; S.pk.ip = ""; S.pk.port = ""; S.pk.proto = ""; S.pk.tag = ""; S.pk.tagLabel = ""; $("#pkSearch").value = ""; $("#pkIp").value = ""; $("#pkPort").value = "";
    $$("#pkChips .chip").forEach((x) => x.classList.toggle("on", x.dataset.p === "")); backToLive(); };
  $("#pkLiveBack").onclick = (e) => { e.preventDefault(); backToLive(); };
  $("#pkPause").onclick = () => { S.pk.paused = !S.pk.paused; $("#pkPause").textContent = S.pk.paused ? "▶ 계속" : "⏸ 일시정지"; renderPackets(); };
  $("#pkMore").onclick = () => loadOlderPackets().catch((e) => toast(e.message, true));
  $("#pkBody").onclick = (e) => { const tr = e.target.closest("tr[data-id]"); if (tr) openPacket(+tr.dataset.id); };
  window.addEventListener("resize", debounce(() => { if (S.lastPacket && S.view === "packets") renderPacketDrawer(); }, 200));
  hooks.setPacketFilter = setPacketFilter;
}
