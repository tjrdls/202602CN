/* 홈 대시보드 */
import { S, $, $$, api, esc, num, bytes, rate, tm, ago, hooks, STATUS_KO, toast as toastMsg } from "../core.js";
import { plot, emptyChart, ensureChart } from "../charts.js";
import { palette, alpha } from "../theme.js";
import { srcPill, sevPill, emptyHtml } from "../ui.js";
import { ipLink } from "../ipdetail.js";
import { selectIssue } from "./issues.js";

export async function loadDashboard() {
  let d;
  try { d = await api("/api/dashboard"); } catch (e) { if (e.offline) hooks.showOffline(); return; }
  S.dash = d; hooks.applyStatus(d.status);
  const P = palette();
  const h = d.health, st = d.stats;
  const color = { good: P.ok, warning: P.warn, danger: P.crit }[h.status];
  $("#ringBar").style.stroke = color;
  $("#ringBar").style.strokeDashoffset = String(326.7 * (1 - h.score / 100));
  $("#score").textContent = h.score;
  $("#score").style.color = color;
  $("#headline").textContent = h.headline;
  $("#heroSub").textContent = `${h.measured_items}개 항목 실측 · ${tm(h.computed_at)} 기준`;
  $("#whyList").innerHTML = h.components.map((c) => `<div class="why-row"><div><div class="why-label">${esc(c.label)}</div><div class="why-detail">${esc(c.detail)}</div></div>
    <div class="why-pen ${c.measured ? (c.penalty > 0 ? "neg" : "zero") : "wait"}">${c.measured ? (c.penalty > 0 ? `−${c.penalty}` : "감점 없음") : "측정 대기"}</div></div>`).join("") +
    `<div class="why-foot">100점에서 실제 측정된 문제만큼 감점해요. 이상 징후(위험 −25, 주의 −10, 정보 −2, 최대 −60), 공유기 손실률×0.4, 인터넷 손실률×0.2, DNS 실패 1건당 −10, 응답 지연 구간별 감점. 80점 이상 정상 · 50~79 주의 · 50 미만 위험.</div>`;
  const hasData = st.total_packets > 0;
  const kv = (id, html, wait) => { const el = $(id); el.innerHTML = html; el.classList.toggle("wait", !!wait); };
  kv("#kPps", hasData ? `${num(Math.round(st.pps))}<small>개/초</small>` : "대기 중", !hasData);
  kv("#kDown", hasData ? rate(st.down_bps) : "대기 중", !hasData);
  kv("#kUp", hasData ? rate(st.up_bps) : "대기 중", !hasData);
  kv("#kTotal", hasData ? num(st.total_packets) : "대기 중", !hasData);
  $("#kTotalFoot").textContent = st.duration_sec ? `${Math.round(st.duration_sec)}초 동안` : "이번 세션";
  kv("#kBytes", hasData ? bytes(st.total_bytes) : "대기 중", !hasData);
  $("#kBytesFoot").textContent = hasData ? `↓ ${bytes(st.down_bytes)} · ↑ ${bytes(st.up_bytes)}` : "";
  const ac = d.anomaly_counts;
  $("#kAnom").innerHTML = `${num(ac.total)}<small>건</small>`;
  $("#kAnom").style.color = ac.danger ? P.crit : ac.warning ? P.warn : "";
  $("#kAnomFoot").textContent = `진행 중 ${ac.active}건 · 위험 ${ac.danger} · 주의 ${ac.warning}`;
  const badge = $("#issueBadge");
  badge.textContent = ac.active; badge.classList.toggle("hidden", !ac.active);

  drawTraffic(st);
  const PR = st.protocols, keys = ["TCP", "UDP", "ICMP", "OTHER"].filter((k) => PR[k].packets);
  if (keys.length) {
    ensureChart("chProto");
    plot("chProto", [{ type: "pie", hole: .62, labels: keys.map((k) => k === "OTHER" ? "기타" : k), values: keys.map((k) => PR[k].packets), sort: false,
      marker: { colors: keys.map((k) => ({ TCP: P.tcp, UDP: P.udp, ICMP: P.icmp, OTHER: P.other }[k])) },
      textinfo: "percent", textposition: "inside", insidetextorientation: "horizontal", textfont: { color: "#fff", size: 12 }, hovertemplate: "%{label}: %{value:,}개 (%{percent})<extra></extra>" }],
      { showlegend: true, legend: { orientation: "h", y: -0.05 }, margin: { l: 8, r: 8, t: 8, b: 8 }, uirevision: "proto" });
  } else emptyChart("chProto", "캡처된 패킷이 없어요");
  const ipMap = {};
  for (const r of st.top_src) ipMap[r.ip] = (ipMap[r.ip] || 0) + r.bytes;
  for (const r of st.top_dst) ipMap[r.ip] = (ipMap[r.ip] || 0) + r.bytes;
  const ips = Object.entries(ipMap).sort((a, b) => b[1] - a[1]).slice(0, 8).reverse();
  if (ips.length) {
    ensureChart("chIp");
    const label = (ip) => (d.names[ip] ? `${d.names[ip]}` : ip) + (d.status.local_ips.includes(ip) ? " (내 컴퓨터)" : "");
    plot("chIp", [{ type: "bar", orientation: "h", y: ips.map(([ip]) => label(ip)), x: ips.map(([, b]) => b), marker: { color: P.primary },
      text: ips.map(([, b]) => bytes(b)), textposition: "outside", cliponaxis: false, hovertemplate: "%{y}<br>%{text}<extra></extra>" }],
      { margin: { l: 130, r: 64, t: 4, b: 20 }, xaxis: { showticklabels: false, showgrid: false }, yaxis: { automargin: true, tickfont: { size: 11 } }, uirevision: "ip" });
  } else emptyChart("chIp", "아직 데이터가 없어요");
  // 주요 통신 장치 목록 (누르면 IP 상세)
  const peers = Object.entries(ipMap).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxB = peers.length ? peers[0][1] : 1;
  $("#peerList").innerHTML = peers.length ? peers.map(([ip, b]) => `<li><div class="l">${ipLink(ip, (d.names[ip] ? d.names[ip] + " · " : "") + ip)}${d.status.local_ips.includes(ip) ? ` <span class="sev-badge b-primary">내 컴퓨터</span>` : ""}<div class="bar-mini"><i style="width:${Math.round(b / maxB * 100)}%"></i></div></div><span class="r">${bytes(b)}</span></li>`).join("")
    : `<li>${emptyHtml("💻", "아직 통신 기록이 없어요")}</li>`;
  // 최근 탐지 이벤트
  const ra = d.recent_anomalies || [];
  $("#recentAnoms").innerHTML = ra.length ? ra.map((a) => `<li data-anom="${a.id}" style="cursor:pointer"><span class="l">${sevPill(a.severity)} ${srcPill(a.source)} ${esc(a.title)}${a.ip ? ` <span class="sub-ip mono">${esc(a.ip)}</span>` : ""}</span><span class="r">${esc(STATUS_KO[a.status] || a.status)} · ${ago(a.last_seen)}</span></li>`).join("")
    : `<li>${emptyHtml("✅", "탐지된 이상 징후가 없어요", "평소와 다른 통신이 보이면 여기에 나타나요")}</li>`;
  $$("#recentAnoms [data-anom]").forEach((li) => li.onclick = () => { hooks.go("issues"); selectIssue(+li.dataset.anom); });
  const ports = st.top_ports.slice(0, 8).reverse();
  if (ports.length) {
    ensureChart("chPort");
    plot("chPort", [{ type: "bar", orientation: "h", y: ports.map((p) => `${p.label} (${p.port})`), x: ports.map((p) => p.bytes), marker: { color: P.info },
      text: ports.map((p) => bytes(p.bytes)), textposition: "outside", cliponaxis: false, hovertemplate: "%{y}<br>%{text}, %{customdata:,}개<extra></extra>", customdata: ports.map((p) => p.packets) }],
      { margin: { l: 130, r: 64, t: 4, b: 20 }, xaxis: { showticklabels: false, showgrid: false }, yaxis: { automargin: true, tickfont: { size: 11 } }, uirevision: "port" });
  } else emptyChart("chPort", "아직 데이터가 없어요");

  $("#feed").innerHTML = d.activity.length ? d.activity.map((a) => {
    const icon = a.kind === "anomaly" ? (a.severity === "danger" ? "🚨" : a.severity === "warning" ? "⚠️" : "ℹ️") : a.kind === "action" ? "🛠️" : "📡";
    const bg = a.kind === "anomaly" ? ({ danger: "var(--crit-soft)", warning: "var(--warn-soft)" }[a.severity] || "var(--surface-2)") : a.kind === "action" ? "var(--ok-soft)" : "var(--primary-soft)";
    const click = a.kind === "anomaly" ? `data-anom="${a.id}"` : a.kind === "action" && a.anomaly_id ? `data-anom="${a.anomaly_id}"` : "";
    return `<li class="${click ? "clickable" : ""}" ${click}><div class="feed-dot" style="background:${bg}">${icon}</div><div><div class="feed-text">${esc(a.text)} ${srcPill(a.source)}</div>
      <div class="feed-time">${ago(a.ts)}${a.status ? " · " + esc(STATUS_KO[a.status] || a.status) : ""}</div></div></li>`;
  }).join("") : `<li>${emptyHtml("🕊️", "아직 기록된 활동이 없어요")}</li>`;
  $$("#feed [data-anom]").forEach((li) => li.onclick = () => { hooks.go("issues"); selectIssue(+li.dataset.anom); });

  const items = [["평균 패킷 크기", `${num(Math.round(st.avg_size))} B`], ["최대 패킷 크기", `${num(st.max_size)} B`], ["세션 평균 PPS", num(Math.round(st.avg_pps_session))],
    ["보낸 장치 수", num(st.unique_src)], ["받은 장치 수", num(st.unique_dst)], ["IPv4 / IPv6", `${num(st.ip_versions.IPv4 || 0)} / ${num(st.ip_versions.IPv6 || 0)}`]];
  $("#statList").innerHTML = items.map(([k, v]) => `<div class="stat-item"><div class="k">${esc(k)}</div><div class="v">${hasData ? esc(v) : "-"}</div></div>`).join("");
  const pr = d.probe;
  if (pr) {
    const g = pr.gateway || {}, e = pr.external || {}, n = pr.dns || {};
    const part = (lbl, p) => p && p.sent ? `${lbl} ${p.avg_ms != null ? p.avg_ms + "ms" : "-"} (손실 ${p.loss_pct}%)` : `${lbl} 측정 실패`;
    $("#probeLine").innerHTML = `🔎 연결 점검 ${ago(pr.measured_at)}: ${esc(part("공유기", g))} · ${esc(part("인터넷", e))} · DNS ${n.tested ? `${n.tested - n.failed}/${n.tested} 성공` : "-"}
      <button class="link-btn" id="probeNow">지금 다시 측정</button>`;
    $("#probeNow").onclick = async () => { try { toastMsg("측정 중이에요…"); await api("/api/probe/run", { method: "POST", body: {} }); loadDashboard(); toastMsg("연결 상태를 다시 측정했어요"); } catch (e) { toastMsg(e.message, true); } };
  } else $("#probeLine").textContent = "🔎 연결 점검(ping·DNS)은 시작 후 몇 초 안에 실행돼요.";
}

export function drawTraffic(st) {
  const P = palette();
  const s = st.series, x = s.map((p) => new Date(p.t * 1000));
  if (!st.total_packets) { emptyChart("chTraffic", "캡처를 시작하면 실시간 그래프가 그려져요"); return; }
  ensureChart("chTraffic");
  const m = S.trafficMode;
  if (m === "packets") {
    plot("chTraffic", [
      { x, y: s.map((p) => p.tcp), name: "TCP", type: "scatter", mode: "lines", stackgroup: "a", line: { width: 0, color: P.tcp }, hovertemplate: "TCP %{y}개<extra></extra>" },
      { x, y: s.map((p) => p.udp), name: "UDP", type: "scatter", mode: "lines", stackgroup: "a", line: { width: 0, color: P.udp }, hovertemplate: "UDP %{y}개<extra></extra>" },
      { x, y: s.map((p) => p.icmp + p.other), name: "ICMP·기타", type: "scatter", mode: "lines", stackgroup: "a", line: { width: 0, color: P.icmp }, hovertemplate: "ICMP·기타 %{y}개<extra></extra>" },
    ], { showlegend: true, legend: { orientation: "h", y: 1.12, x: 0 }, yaxis: { title: { text: "패킷/초", font: { size: 11 } } }, hovermode: "x unified", uirevision: "t1" });
  } else if (m === "bytes") {
    plot("chTraffic", [{ x, y: s.map((p) => p.bytes * 8 / 1e6), type: "scatter", mode: "lines", fill: "tozeroy", line: { color: P.primary, width: 2, shape: "spline" },
      fillcolor: alpha(P.primary, P.fillAlpha), hovertemplate: "%{y:.2f} Mbps<extra></extra>" }], { yaxis: { title: { text: "Mbps", font: { size: 11 } } }, hovermode: "x unified", uirevision: "t2" });
  } else {
    plot("chTraffic", [
      { x, y: s.map((p) => p.down * 8 / 1e6), name: "다운로드", type: "scatter", mode: "lines", fill: "tozeroy", line: { color: P.down, width: 2 }, fillcolor: alpha(P.down, P.fillAlpha), hovertemplate: "↓ %{y:.2f} Mbps<extra></extra>" },
      { x, y: s.map((p) => -p.up * 8 / 1e6), name: "업로드", type: "scatter", mode: "lines", fill: "tozeroy", line: { color: P.up, width: 2 }, fillcolor: alpha(P.up, P.fillAlpha),
        customdata: s.map((p) => p.up * 8 / 1e6), hovertemplate: "↑ %{customdata:.2f} Mbps<extra></extra>" },
    ], { showlegend: true, legend: { orientation: "h", y: 1.12, x: 0 }, yaxis: { title: { text: "↑ 업로드 · ↓ 다운로드 (Mbps)", font: { size: 11 } }, rangemode: "normal" }, hovermode: "x unified", uirevision: "t3" });
  }
}
export function bindHome() {
  $("#whyBtn").onclick = () => { const w = $("#whyList"); w.classList.toggle("hidden"); $("#whyBtn").textContent = w.classList.contains("hidden") ? "왜 이 점수인가요?" : "접기"; };
  $$("#trafficSeg button").forEach((b) => b.onclick = () => { $$("#trafficSeg button").forEach((x) => x.classList.toggle("on", x === b)); S.trafficMode = b.dataset.k; if (S.dash) drawTraffic(S.dash.stats); });
}
