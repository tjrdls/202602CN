/* 모달·드로어·배지 등 화면 공용 조각 */
import { $, S, SEV, SEV_CLASS, esc } from "./core.js";

export const sevPill = (s) => `<span class="sev-badge ${SEV_CLASS[s] || "s-info"}">${esc(SEV[s] || s)}</span>`;
export const srcPill = (src) => src === "test" ? `<span class="sev-badge s-test">테스트 데이터</span>` : src === "pcap" ? `<span class="sev-badge s-pcap">파일 분석</span>`
  : src === "sim" ? `<span class="sev-badge s-sim">시뮬레이션</span>` : "";
export const emptyHtml = (icon, title, sub = "") => `<div class="empty"><div class="empty-icon">${icon}</div><div class="empty-title">${esc(title)}</div>${sub ? `<div>${sub}</div>` : ""}</div>`;
export const loadingHtml = (msg = "불러오는 중…") => `<div class="loading">${esc(msg)}</div>`;
export const errorHtml = (msg, help = "") => `<div class="error-box"><b>${esc(msg)}</b>${esc(help)}</div>`;

export function modal(html, size = false) {
  const card = $("#modalCard");
  card.className = "modal-card" + (size === true || size === "wide" ? " wide" : size === "xl" ? " xl" : "");
  card.innerHTML = html;
  $("#modal").classList.add("show");
}
export function closeModal() { $("#modal").classList.remove("show"); }
export function openDrawer(html) { $("#drawer").innerHTML = html; $("#drawer").classList.add("show"); $("#scrim").classList.add("show"); }
export function closeDrawer() { $("#drawer").classList.remove("show"); $("#scrim").classList.remove("show"); S.lastPacket = null; }
export function isModalOpen() { return $("#modal").classList.contains("show"); }
export function isDrawerOpen() { return $("#drawer").classList.contains("show"); }
