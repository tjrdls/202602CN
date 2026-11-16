/* 테마(라이트/다크/자동)와 차트 색. 설정은 localStorage "nc.theme" = auto | light | dark.
 * index.html 의 인라인 스크립트가 첫 그리기 전에 data-theme 를 미리 정하고, 여기서는 전환·구독·차트 팔레트를 맡는다. */
const KEY = "nc.theme";
const mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
const listeners = new Set();

export function themePref() { return localStorage.getItem(KEY) || "auto"; }
export function resolvedTheme() { return document.documentElement.dataset.theme === "dark" ? "dark" : "light"; }
export function applyTheme(pref = themePref()) {
  const dark = pref === "dark" || (pref === "auto" && mq && mq.matches);
  const next = dark ? "dark" : "light";
  const changed = document.documentElement.dataset.theme !== next;
  document.documentElement.dataset.theme = next;
  document.documentElement.dataset.themePref = pref;
  if (changed) for (const fn of listeners) { try { fn(next); } catch (e) { /* 개별 리스너 오류 무시 */ } }
  return next;
}
export function setThemePref(pref) { localStorage.setItem(KEY, pref); return applyTheme(pref); }
export function toggleTheme() { return setThemePref(resolvedTheme() === "dark" ? "light" : "dark"); }
export function onThemeChange(fn) { listeners.add(fn); return () => listeners.delete(fn); }
if (mq) mq.addEventListener("change", () => { if (themePref() === "auto") applyTheme("auto"); });

/* CSS 토큰 읽기 (차트는 CSS 변수를 직접 못 쓰므로 계산된 값을 넘긴다) */
export const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
export function palette() {
  return {
    primary: cssVar("--primary"), ok: cssVar("--ok"), warn: cssVar("--warn"), crit: cssVar("--crit"), info: cssVar("--info"), sim: cssVar("--sim"), muted: cssVar("--muted"),
    tcp: cssVar("--chart-tcp"), udp: cssVar("--chart-udp"), icmp: cssVar("--chart-icmp"), other: cssVar("--chart-other"), down: cssVar("--chart-down"), up: cssVar("--chart-up"),
    text: cssVar("--text-1"), text2: cssVar("--text-2"), text3: cssVar("--text-3"), grid: cssVar("--chart-grid"), chartText: cssVar("--chart-text"),
    surface: cssVar("--surface"), surfaceInv: cssVar("--surface-inv"), textInv: cssVar("--text-inv"), fillAlpha: Number(cssVar("--chart-fill-alpha") || .12),
    okText: cssVar("--ok-text"), critText: cssVar("--crit-text"), warnText: cssVar("--warn-text"),
  };
}
/* "#RRGGBB" → "rgba(r,g,b,a)" */
export function alpha(hex, a) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}
