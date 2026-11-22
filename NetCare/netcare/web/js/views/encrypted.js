/* 패킷 분석 화면의 '암호화 통신 분석' 패널 + 패킷 상세의 암호화 분석 블록 */
import { S, $, $$, api, esc, num, bytes, pct, tm, toast } from "../core.js";
import { modal, emptyHtml } from "../ui.js";

const ST = { confirmed: ["확인됨", "s-good"], estimated: ["추정됨", "s-warning"], limited: ["분석 제한", "s-info"], failed: ["분석 실패", "s-danger"] };
export const stPill = (s) => s && ST[s] ? `<span class="sev-badge enc-st ${ST[s][1]}">${ST[s][0]}</span>` : "";
let last = 0, onPick = null;

export function bindEncrypted(pick) {
  onPick = pick;
  $("#encGrid").onclick = (e) => { const k = e.target.closest("[data-tag]"); if (k) onPick({ tag: k.dataset.tag, label: k.dataset.label, proto: k.dataset.proto || "" }); };
  $("#encBars").onclick = (e) => { const k = e.target.closest("[data-tag]"); if (k) onPick({ tag: k.dataset.tag, label: k.dataset.label, proto: k.dataset.proto || "" }); };
  $("#encEvents").onclick = (e) => { e.preventDefault(); e.stopPropagation(); openEvents(); };
}

export async function loadEncrypted(force = false) {
  if (!force && Date.now() - last < 2500) return;
  last = Date.now();
  try { render((await api("/api/encrypted")).summary); } catch (e) { /* 패널은 조용히 실패 */ }
}

function tile(label, value, foot, tag, proto = "") {
  const on = S.pk.tag === tag && tag ? " on" : "";
  return `<div class="card kpi${on}" data-tag="${esc(tag || "")}" data-proto="${esc(proto)}" data-label="${esc(label)}" title="누르면 관련 패킷만 보여요">
    <div class="kpi-label">${esc(label)}</div><div class="kpi-value ${value === "-" ? "wait" : ""}">${value}</div><div class="kpi-foot">${foot}</div></div>`;
}

function render(s) {
  const pb = s.protocol_bytes || {}, tot = (pb.TCP || 0) + (pb.UDP || 0) + (pb.QUIC || 0) + (pb["기타"] || 0);
  const share = (k) => tot ? pct((pb[k] || 0) / tot) : "-";
  const sni = s.sni || {}, ech = s.ech || {}, r = s.reassembly || {}, d = s.dns || {}, q = s.quic || {};
  const dohN = (d.flows || {}).doh || 0, doqN = (d.flows || {}).doq || 0, dotN = (d.flows || {}).dot || 0;
  $("#encGrid").innerHTML = [
    tile("SNI 추출 성공률", sni.attempts ? pct(sni.success_rate) : "-", `실제 도메인 확정 ${sni.attempts ? pct(sni.real_domain_rate) : "-"} · 확정 불가(ECH 확장) ${num(sni.estimated)} · 실패 ${num(sni.failed)}`, "sni_ok"),
    tile("ECH 관련", num((ech.confirmed || 0) + (ech.unconfirmed || 0)), `ECH 확실 ${num(ech.confirmed)} · 확장만 있음(확정 불가) ${num(ech.unconfirmed)}`, "ech_ext"),
    tile("QUIC / HTTP3", num(q.hello_ok || 0), `HTTP/3 ${num(q.http3 || 0)} · 복호화 실패 ${num(q.decrypt_failed || 0)} · 미지원 버전 ${num(q.unsupported || 0)}`, "quic"),
    tile("TCP 재조립", num(r.complete || 0), `여러 조각 ${num(r.multi_segment || 0)} · 실패 ${num(r.failed || 0)}${r.conflicts ? ` · 충돌 ${num(r.conflicts)}` : ""}`, r.failed ? "reasm_fail" : "reasm_multi"),
    tile("암호화 DNS 의심·확인", num(dohN + doqN + dotN), `DoH 추정 ${num(dohN)} · DoQ ${num(doqN)} · DoT ${num(dotN)}`, dohN ? "doh_est" : (doqN ? "doq" : "dot")),
    tile("분석할 수 없는 트래픽", s.opaque && s.opaque.share != null ? pct(s.opaque.share) : "-", `암호화된 내용 ${bytes((s.opaque || {}).bytes || 0)}`, "opaque"),
  ].join("");
  const vers = Object.entries(s.tls_versions || {}).filter(([k]) => !k.includes("서버"));
  const srv = Object.entries(s.tls_versions || {}).filter(([k]) => k.includes("서버"));
  const pq = s.pqc || {};
  const dnsB = d.bytes || {}, dnsTot = Object.values(dnsB).reduce((a, b) => a + b, 0);
  $("#encBars").innerHTML = `
    <div class="enc-bar"><h4>프로토콜별 통신량</h4>
      ${[["TCP", "TCP", ""], ["UDP (QUIC 제외)", "UDP", ""], ["QUIC", "QUIC", "quic"]].map(([lb, k, tag]) => `<div class="enc-row" data-tag="${tag}" data-proto="${tag ? "" : k}" data-label="${esc(lb)}"><span>${esc(lb)}</span><b>${share(k)} · ${bytes(pb[k] || 0)}</b></div>`).join("")}</div>
    <div class="enc-bar"><h4>TLS 버전 (클라이언트 제안 최고 버전)</h4>
      ${vers.length ? vers.map(([k, v]) => `<div class="enc-row" data-tag="${k === "TLS 1.3" ? "tls13" : "tls"}" data-label="${esc(k)}"><span>${esc(k)}</span><b>${num(v)}건</b></div>`).join("") : `<div class="card-sub">아직 핸드셰이크가 없어요</div>`}
      ${srv.map(([k, v]) => `<div class="enc-row"><span class="sub-ip">${esc(k)}</span><b>${num(v)}건</b></div>`).join("")}
      <div class="enc-row" data-tag="pqc" data-label="PQC 하이브리드 키 교환"><span>PQC 하이브리드 키 교환</span><b>제안 ${num(pq.offered || 0)} · 서버 선택(확인) ${num(pq.negotiated || 0)}</b></div></div>
    <div class="enc-bar"><h4>DNS 종류별 통신량</h4>
      ${[["dns", "일반 DNS (도메인 보임)"], ["dot", "DoT (확인)"], ["doq", "DoQ"], ["doh", "DoH (추정)"]].map(([k, lb]) => `<div class="enc-row" data-tag="${k === "doh" ? "doh_est" : k}" data-label="${esc(lb)}"><span>${esc(lb)}</span><b>${dnsTot ? pct((dnsB[k] || 0) / dnsTot) : "-"} · ${num((d.packets || {})[k] || 0)}패킷</b></div>`).join("")}</div>`;
  $("#encNote").textContent = "ECH·PQC는 서로 다른 기술이에요: ECH는 접속 도메인을 숨기고, PQC(양자내성 하이브리드 키 교환)는 키 교환을 강화할 뿐 도메인을 숨기지 않아요. "
    + "NetCare의 이상 탐지 규칙은 SNI(도메인)를 쓰지 않아 ECH 환경에서도 IP·포트·패턴으로 동작해요.";
}

async function openEvents(status = "") {
  let evs = [];
  try { evs = (await api("/api/encrypted/events?limit=200" + (status ? `&status=${status}` : ""))).events; } catch (e) { toast(e.message, true); return; }
  const rows = evs.map((e) => {
    const h = e.hello || {}, sv = e.sni || {};
    const name = sv.real_sni || (sv.outer_sni ? `공개 이름 ${sv.outer_sni}` : (sv.observed_sni ? `${sv.observed_sni} (확정 불가)` : "-"));
    return `<tr ${e.packet_id ? `data-pid="${e.packet_id}" style="cursor:pointer"` : ""}><td>${tm(e.ts)}</td><td>${esc(e.kind)}</td><td>${stPill(e.status)}</td>
      <td class="mono">${esc((e.dst || "") + (e.dport ? ":" + e.dport : ""))}</td><td>${esc(name)}</td><td>${esc(h.tls_version || "")}</td>
      <td>${esc((h.alpn || []).join(","))}</td><td>${h.hybrid ? "PQC" : ""}</td><td class="card-sub" style="margin:0">${esc(e.note || "")}</td></tr>`;
  }).join("");
  modal(`<div class="modal-head"><h3>암호화 통신 분석 기록</h3></div>
    <div class="seg" id="encSt">${[["", "전체"], ["confirmed", "확인됨"], ["estimated", "추정됨"], ["limited", "분석 제한"], ["failed", "분석 실패"]].map(([k, l]) => `<button class="${k === status ? "on" : ""}" data-s="${k}">${l}</button>`).join("")}</div>
    <div class="table-wrap" style="max-height:60vh;margin-top:10px"><table><thead><tr><th>시각</th><th>종류</th><th>상태</th><th>서버</th><th>도메인(SNI)</th><th>TLS</th><th>ALPN</th><th>키 교환</th><th>설명</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="9">${emptyHtml("🔐", "아직 분석한 핸드셰이크가 없어요")}</td></tr>`}</tbody></table></div>
    <div class="card-sub">행을 누르면 그 패킷의 상세(재조립 상태·확장 필드)를 열어요.</div>`, "xl");
  $$("#encSt [data-s]").forEach((b) => b.onclick = () => openEvents(b.dataset.s));
  $$("#modal tr[data-pid]").forEach((tr) => tr.onclick = () => { document.querySelector("#modal").classList.remove("show"); window.App.openPacket(+tr.dataset.pid); });
}

/* 패킷 상세 안의 '암호화 통신 분석' 블록 */
export function encDetailHtml(e) {
  if (!e) return "";
  const h = e.hello || {}, sv = e.sni || {}, ra = e.reassembly || {}, q = e.quic || {};
  const easy = `<div class="kv">
    <div class="k">분석 상태</div><div class="v">${stPill(e.status)} ${esc(e.note || "")}</div>
    ${sv.real_sni ? `<div class="k">접속 도메인</div><div class="v">${esc(sv.real_sni)} <span class="sub-ip">(확인됨)</span></div>` : ""}
    ${sv.outer_sni ? `<div class="k">ECH 공개 이름</div><div class="v">${esc(sv.outer_sni)} <span class="sub-ip">(실제 도메인 아님)</span></div>` : ""}
    ${!sv.real_sni && !sv.outer_sni && sv.observed_sni ? `<div class="k">보이는 이름</div><div class="v">${esc(sv.observed_sni)} <span class="sub-ip">(실제 도메인인지 확정 불가)</span></div>` : ""}
    ${h.tls_version ? `<div class="k">TLS 버전</div><div class="v">${esc(h.tls_version)}</div>` : ""}
    ${h.alpn && h.alpn.length ? `<div class="k">응용 프로토콜 제안</div><div class="v">${esc(h.alpn.join(", "))}</div>` : ""}
    ${h.hybrid || h.group ? `<div class="k">키 교환</div><div class="v">${esc(h.group || (h.key_share || []).map((k) => k.group).join(", "))}${h.hybrid ? " · PQC 하이브리드" : ""}</div>` : ""}
    ${q.version ? `<div class="k">QUIC</div><div class="v">${esc(q.version)}${q.application ? " · " + esc(q.application) : ""}</div>` : ""}
    ${ra.status ? `<div class="k">TCP 재조립</div><div class="v">${ra.status === "complete" ? `${num(ra.segments)}개 조각을 순서 번호로 이어 ${num(ra.bytes)}바이트 복원` : esc(ra.reason || "실패")}${ra.reordered ? ` · 순서 뒤바뀜 ${ra.reordered}` : ""}${ra.duplicates ? ` · 중복 ${ra.duplicates}` : ""}${ra.conflicts ? ` · 충돌 ${ra.conflicts}` : ""}</div>` : ""}
  </div>`;
  const expert = S.expert ? `<details class="more" open><summary>원본 분석 값 (확장 필드·재조립 상태)</summary><pre class="hex" style="white-space:pre-wrap">${esc(JSON.stringify({ hello: h, sni: sv, reassembly: ra, quic: q }, null, 2))}</pre></details>` : "";
  return `<div class="section-h">암호화 통신 분석</div><div class="card tight">${easy}</div>${expert}`;
}
