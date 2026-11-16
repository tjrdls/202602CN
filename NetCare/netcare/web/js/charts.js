/* Plotly 래퍼. 레이아웃과 색을 테마 토큰에서 읽어 모든 차트가 같은 모양을 갖게 한다. */
import { esc } from "./core.js";
import { palette } from "./theme.js";

export const baseLayout = () => {
  const P = palette();
  return {
    margin: { l: 44, r: 12, t: 8, b: 32 }, paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    font: { family: getComputedStyle(document.body).fontFamily, size: 12, color: P.chartText },
    xaxis: { gridcolor: P.grid, zeroline: false, showline: false, tickfont: { color: P.chartText } },
    yaxis: { gridcolor: P.grid, zeroline: false, rangemode: "tozero", tickfont: { color: P.chartText } },
    showlegend: false, legend: { font: { color: P.text2 } },
    hoverlabel: { bgcolor: P.surfaceInv, bordercolor: P.surfaceInv, font: { color: P.textInv, size: 12 } },
    colorway: [P.primary, P.ok, P.warn, P.crit, P.sim, P.info, P.muted],
  };
};
export function plot(id, data, layout = {}) {
  const el = document.getElementById(id);
  if (!el || !window.Plotly) return;
  const base = baseLayout();
  const L = Object.assign(base, layout);
  if (layout.xaxis) L.xaxis = Object.assign(baseLayout().xaxis, layout.xaxis);
  if (layout.yaxis) L.yaxis = Object.assign(baseLayout().yaxis, layout.yaxis);
  if (layout.legend) L.legend = Object.assign(baseLayout().legend, layout.legend);
  if (el.querySelector(".empty")) el.innerHTML = "";
  Plotly.react(el, data, L, { displayModeBar: false, responsive: true });
}
export function emptyChart(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  if (window.Plotly && el.data) Plotly.purge(el);
  el.innerHTML = `<div class="empty sm">${esc(msg)}</div>`;
}
export function ensureChart(id) { const el = document.getElementById(id); if (el && el.querySelector(".empty")) el.innerHTML = ""; }
/* 테마가 바뀌면 이미 그려진 차트의 색만 다시 입힌다 */
export function restyleAll() {
  if (!window.Plotly) return;
  const base = baseLayout();
  for (const el of document.querySelectorAll(".chart")) {
    if (!el.data || !el.layout) continue;
    Plotly.relayout(el, { "font.color": base.font.color, "xaxis.gridcolor": base.xaxis.gridcolor, "yaxis.gridcolor": base.yaxis.gridcolor,
      "xaxis.tickfont.color": base.font.color, "yaxis.tickfont.color": base.font.color, "legend.font.color": base.legend.font.color,
      "hoverlabel.bgcolor": base.hoverlabel.bgcolor, "hoverlabel.bordercolor": base.hoverlabel.bordercolor, "hoverlabel.font.color": base.hoverlabel.font.color });
  }
}
