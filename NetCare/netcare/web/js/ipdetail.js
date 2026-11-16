/* IP 상세 팝업: 보관 중인 패킷·이상 징후 기록을 모아 한 장치를 설명한다 */
import { S, $, $$, api, esc, num, bytes, dt, ago, toast, hooks, STATUS_KO } from "./core.js";
import { modal, closeModal, loadingHtml, sevPill, srcPill } from "./ui.js";

export const ipLink = (ip, label = null) => ip ? `<span class="ip-link" data-ip="${esc(ip)}" title="IP 상세 보기">${esc(label ?? ip)}</span>` : "";

export async function openIpDetail(ip) {
  modal(loadingHtml("장치 정보를 모으는 중…"), true);
  let d;
  try { d = await api(`/api/ip/${encodeURIComponent(ip)}`); } catch (e) { modal(`<h3>${esc(ip)}</h3><div class="error-box"><b>불러오지 못했어요</b>${esc(e.message)}</div><div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button></div>`); return; }
  const flags = [];
  if (d.is_local) flags.push(`<span class="sev-badge b-primary">내 컴퓨터</span>`);
  if (d.is_gateway) flags.push(`<span class="sev-badge b-info">공유기(게이트웨이)</span>`);
  if (d.is_dns_server) flags.push(`<span class="sev-badge b-info">DNS 서버</span>`);
  if (d.whitelisted) flags.push(`<span class="sev-badge s-good">화이트리스트</span>`);
  if (d.name) flags.push(`<span class="sev-badge b-neutral">도메인 ${esc(d.name)}</span>`);
  const total = (d.sent.bytes || 0) + (d.received.bytes || 0);
  const maxPeer = Math.max(1, ...d.peers.map((p) => p.bytes || 0));
  const openAnoms = d.anomalies.filter((a) => ["active", "ended"].includes(a.status)).length;
  modal(`<div class="row" style="justify-content:space-between;align-items:flex-start"><div><h3 style="margin-bottom:2px">${esc(d.label)}</h3><div class="mono" style="color:var(--text-3)">${esc(d.ip)}</div></div>
      <span class="sub-ip">${d.scope === "session" ? "이번 세션 기준" : "보관 중인 기록 기준"}</span></div>
    <div class="flag-row">${flags.join("") || `<span class="sev-badge b-neutral">외부 장치</span>`}</div>
    <div class="metric-grid">
      <div class="metric"><div class="k">보낸 데이터</div><div class="v">${bytes(d.sent.bytes)}</div><div class="sub-ip">${num(d.sent.packets)}개 패킷</div></div>
      <div class="metric"><div class="k">받은 데이터</div><div class="v">${bytes(d.received.bytes)}</div><div class="sub-ip">${num(d.received.packets)}개 패킷</div></div>
      <div class="metric"><div class="k">처음 · 마지막</div><div class="v" style="font-size:var(--fs-md)">${d.first_ts ? dt(d.first_ts) : "-"}</div><div class="sub-ip">${d.last_ts ? "마지막 " + ago(d.last_ts) : "기록 없음"}</div></div>
      <div class="metric"><div class="k">관련 이상 징후</div><div class="v ${openAnoms ? "sev-text-danger" : ""}">${d.anomalies.length}<small>건</small></div><div class="sub-ip">${openAnoms ? `확인 필요 ${openAnoms}건` : "확인 필요 없음"}</div></div>
    </div>
    <div class="grid g-2 mt">
      <div><div class="section-h" style="margin-top:0">많이 통신한 상대</div>
        ${d.peers.length ? `<ul class="list-plain">${d.peers.map((p) => `<li><div class="l">${ipLink(p.peer)}<div class="bar-mini"><i style="width:${Math.round((p.bytes || 0) / maxPeer * 100)}%"></i></div></div><span class="r">${bytes(p.bytes)}</span></li>`).join("")}</ul>` : `<div class="empty sm">기록 없음</div>`}</div>
      <div><div class="section-h" style="margin-top:0">이 장치가 받은 포트 · 프로토콜</div>
        ${d.ports.length ? `<ul class="list-plain">${d.ports.map((p) => `<li><span class="l"><span class="proto p-${esc(p.proto)}">${esc(p.service || p.proto)}</span> <span class="mono">${p.port}</span></span><span class="r">${num(p.packets)}개</span></li>`).join("")}</ul>` : `<div class="empty sm">받은 포트 기록 없음</div>`}
        <div class="sub-ip" style="margin-top:6px">${d.protocols.map((p) => `${esc(p.proto)} ${num(p.packets)}`).join(" · ")}</div></div>
    </div>
    ${d.anomalies.length ? `<div class="section-h">관련 이상 징후</div><ul class="list-plain">${d.anomalies.map((a) => `<li data-anom="${a.id}" style="cursor:pointer"><span class="l">${sevPill(a.severity)} ${srcPill(a.source)} ${esc(a.title)}</span><span class="r">${esc(STATUS_KO[a.status] || a.status)} · ${ago(a.last_seen)}</span></li>`).join("")}</ul>` : ""}
    <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button>
      <button class="btn btn-tonal" id="ipPk">이 IP 패킷만 보기</button>
      ${!d.is_local && !d.whitelisted ? `<button class="btn btn-secondary" id="ipWl">화이트리스트 추가</button>` : ""}</div>`, true);
  $("#ipPk").onclick = () => { closeModal(); hooks.go("packets"); hooks.setPacketFilter && hooks.setPacketFilter({ ip: d.ip }); };
  const wl = $("#ipWl");
  if (wl) wl.onclick = async () => {
    try {
      const c = await api("/api/settings");
      const list = c.detection.whitelist.includes(d.ip) ? c.detection.whitelist : [...c.detection.whitelist, d.ip];
      await api("/api/settings", { method: "PUT", body: { detection: { whitelist: list } } });
      toast(`${d.ip} 를 화이트리스트에 추가했어요`); openIpDetail(d.ip);
    } catch (e) { toast(e.message, true); }
  };
  $$("#modalCard [data-anom]").forEach((li) => li.onclick = () => { closeModal(); hooks.go("issues/" + li.dataset.anom); });
}
