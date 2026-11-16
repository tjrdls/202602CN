/* 공용 상태·유틸. 화면 모듈이 서로 직접 참조하지 않도록 hooks 로 느슨하게 연결한다.
 * 서버에서 온 문자열은 항상 esc()로 이스케이프한다. */
export const S = {
  view: "home", expert: localStorage.getItem("nc.expert") === "1",
  status: null, dash: null, trafficMode: "packets",
  pk: { rows: [], lastId: 0, oldestId: null, proto: "", q: "", paused: false, sessionId: null, newIds: new Set() },
  is: { filter: "open", list: [], sel: null, detail: null },
  rp: { days: 7, ipKey: "top_src", data: null },
  catalog: null, lastPacket: null,
};
/* main.js 가 채운다: go(view), tick(), applyStatus(st), showOffline() */
export const hooks = { go: () => {}, tick: () => {}, applyStatus: () => {}, showOffline: () => {}, setPacketFilter: null, openRule: null };

export const $ = (s, el = document) => el.querySelector(s);
export const $$ = (s, el = document) => [...el.querySelectorAll(s)];

export const SEV = { danger: "위험", warning: "주의", info: "정보" };
export const SEV_CLASS = { danger: "s-danger", warning: "s-warning", info: "s-info", good: "s-good" };
export const STATUS_KO = { active: "진행 중", ended: "멈춤", resolved: "조치 완료", dismissed: "정상 처리" };
export const ACT_STATUS = { success: "완료", failed: "실패", simulated: "시뮬레이션", running: "실행 중", cancelled: "취소", rolled_back: "되돌림" };
export const TYPE_ICON = { ip_packet_flood: "🌊", syn_surge: "🔁", port_concentration: "🎯", traffic_surge: "📈", repeated_connection: "🔂",
  port_scan: "🔍", heavy_peer: "📦", dns_failure: "🧭", gateway_unreachable: "📶", packet_loss: "📉", high_latency: "🐢",
  arp_spoof: "🪤", ip_spoof_suspect: "🎭", dns_spoof_suspect: "🧪", latency_rise: "🐢", jitter_high: "〰️", tcp_loss: "📉", connection_failure: "🔌", bandwidth_limit_suspect: "🚦", packet_size_anomaly: "📏", proto_ratio_shift: "🧩", dns_nxdomain_surge: "❓" };
export const typeLabel = (t) => ({ ip_packet_flood: "과다 패킷", syn_surge: "SYN 급증", port_concentration: "포트 집중", traffic_surge: "사용량 급증", repeated_connection: "반복 연결",
  port_scan: "포트 스캔", heavy_peer: "과다 통신", dns_failure: "DNS 실패", gateway_unreachable: "공유기 끊김", packet_loss: "데이터 손실", high_latency: "지연",
  arp_spoof: "ARP 스푸핑 의심", ip_spoof_suspect: "IP 스푸핑 의심", dns_spoof_suspect: "DNS 위조 의심",
  latency_rise: "지연 증가", jitter_high: "지터", tcp_loss: "데이터 손실", connection_failure: "연결 중단", bandwidth_limit_suspect: "대역폭 제한 의심", packet_size_anomaly: "패킷 크기 이상", proto_ratio_shift: "프로토콜 비율 이상", dns_nxdomain_surge: "NXDOMAIN 급증" }[t] || t);

export function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
export async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: { "X-NetCare": "1" } };
  if (opts.body !== undefined) {
    if (opts.body instanceof FormData) o.body = opts.body;
    else { o.body = JSON.stringify(opts.body); o.headers["Content-Type"] = "application/json"; }
  }
  let res;
  try { res = await fetch(path, o); } catch (e) { throw Object.assign(new Error("NetCare 서버에 연결할 수 없어요. 프로그램이 실행 중인지 확인해 주세요."), { offline: true }); }
  let data = null;
  try { data = await res.json(); } catch (e) { /* 비 JSON */ }
  if (!res.ok) {
    const err = new Error((data && (data.detail || data.message)) || `요청 실패 (${res.status})`);
    Object.assign(err, data || {}, { status: res.status });
    throw err;
  }
  return data;
}
export function toast(msg, err = false) {
  const t = document.createElement("div");
  t.className = "toast" + (err ? " err" : "");
  t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), err ? 5200 : 3000);
}
export const num = (n) => (n ?? 0).toLocaleString("ko-KR");
export function bytes(n) {
  n = Number(n || 0); const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n.toFixed(0)} B` : `${n.toFixed(1)} ${u[i]}`;
}
export function rate(bps) {
  let b = Number(bps || 0) * 8; const u = ["bps", "Kbps", "Mbps", "Gbps"]; let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return i === 0 ? `${b.toFixed(0)} bps` : `${b.toFixed(1)} ${u[i]}`;
}
export const p2 = (v) => String(v).padStart(2, "0");
export const tm = (ts) => { if (!ts) return "-"; const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
export const dt = (ts) => { if (!ts) return "-"; const d = new Date(ts * 1000); return `${p2(d.getMonth() + 1)}/${p2(d.getDate())} ${tm(ts)}`; };
export function ago(ts) {
  if (!ts) return "";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 10) return "방금";
  if (s < 60) return `${Math.floor(s)}초 전`;
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  return dt(ts);
}
export const pct = (v) => v == null ? "-" : `${(v * 100).toFixed(1)}%`;
export const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
