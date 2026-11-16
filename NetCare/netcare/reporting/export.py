"""리포트 내보내기: CSV (pandas) 와 PDF (ReportLab, 한글 폰트 내장)."""
from __future__ import annotations

import io
import json
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

from netcare.analysis import terms
from netcare.diagnosis.explainer import TYPE_LABELS
from netcare.detection.detector import SEVERITY_KO

FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "C:/Windows/Fonts/malgun.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
]

CSV_COLUMNS_KO = {
    "id": "번호", "ts": "시각", "length": "크기(바이트)", "src": "보내는 장치", "dst": "받는 장치", "proto": "프로토콜",
    "sport": "보내는 포트", "dport": "받는 포트", "flags": "TCP 플래그", "ttl": "TTL", "direction": "방향",
    "service": "서비스", "info": "기술 정보", "friendly": "쉬운 설명", "source": "데이터 출처",
}


def _fmt_ts(x):
    try:
        return datetime.fromtimestamp(float(x)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


def to_csv(kind: str, rows: list[dict]) -> bytes:
    df = pd.DataFrame(rows)
    if df.empty:
        df = pd.DataFrame({"안내": ["선택한 기간에 데이터가 없어요"]})
    else:
        for col in ("ts", "detected_at", "last_seen", "created_at", "rolled_back_at", "expires_at"):
            if col in df:
                df[col] = df[col].map(_fmt_ts)
        if "minute" in df:
            df["minute"] = df["minute"].map(lambda m: _fmt_ts(m * 60))
        for col in df.columns:
            if df[col].map(lambda v: isinstance(v, (dict, list))).any():
                df[col] = df[col].map(lambda v: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v)
        if kind == "anomalies":
            df["type"] = df["type"].map(lambda t: TYPE_LABELS.get(t, t))
            df["severity"] = df["severity"].map(lambda s: SEVERITY_KO.get(s, s))
            df = df.drop(columns=[c for c in ("explanation",) if c in df])
        if kind == "packets":
            df = df.rename(columns=CSV_COLUMNS_KO)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return ("\ufeff" + buf.getvalue()).encode("utf-8")  # BOM: 엑셀에서 한글이 깨지지 않게


def _font() -> str:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            try:
                pdfmetrics.registerFont(TTFont("NetCareKR", path))
                return "NetCareKR"
            except Exception:
                continue
    raise RuntimeError("PDF에 쓸 한글 폰트를 찾지 못했어요. (macOS: AppleGothic, Windows: 맑은 고딕, Linux: 나눔고딕 설치 필요)")


def to_pdf(report: dict, start: float, end: float, include_test: bool) -> bytes:
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    font = _font()
    green = colors.HexColor("#00B26B")
    gray = colors.HexColor("#8B95A1")
    h1 = ParagraphStyle("h1", fontName=font, fontSize=20, leading=26, textColor=colors.HexColor("#191F28"))
    h2 = ParagraphStyle("h2", fontName=font, fontSize=13, leading=18, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#191F28"))
    body = ParagraphStyle("b", fontName=font, fontSize=9.5, leading=14, textColor=colors.HexColor("#333D4B"))
    small = ParagraphStyle("s", fontName=font, fontSize=8, leading=11, textColor=gray)

    def table(data, widths):
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F4F6")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#4E5968")),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E8EB")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    story = []
    period = f"{datetime.fromtimestamp(start):%Y-%m-%d} ~ {datetime.fromtimestamp(end):%Y-%m-%d}"
    story += [Paragraph("NetCare 네트워크 리포트", h1),
              Paragraph(f"기간: {period} · 생성: {datetime.now():%Y-%m-%d %H:%M} · 데이터: {'실제 캡처 + 테스트/파일 데이터 포함' if include_test else '실제 캡처 데이터만'}", small),
              Spacer(1, 6 * mm)]
    p = report.get("protocols") or {}
    total = p.get("total") or 0
    story.append(Paragraph("요약", h2))
    anoms = report.get("anomalies") or []
    sev_cnt = {s: sum(1 for a in anoms if a["severity"] == s) for s in ("danger", "warning", "info")}
    hs = [h["score"] for h in report.get("health") or [] if h.get("score") is not None]
    summary = [["항목", "값"],
               ["전체 패킷 수", f"{total:,}"], ["전체 전송량", terms.human_bytes(p.get("bytes") or 0)],
               ["이상 징후", f"위험 {sev_cnt['danger']} · 주의 {sev_cnt['warning']} · 정보 {sev_cnt['info']}"],
               ["건강 점수(평균/최저)", f"{sum(hs) / len(hs):.0f} / {min(hs)}" if hs else "기록 없음"]]
    story.append(table(summary, [60 * mm, 110 * mm]))

    daily = report.get("daily") or []
    story.append(Paragraph("일별 네트워크 사용량", h2))
    if daily:
        d = Drawing(170 * mm, 55 * mm)
        bc = VerticalBarChart()
        bc.x, bc.y, bc.width, bc.height = 30, 20, 150 * mm, 40 * mm
        bc.data = [[(r["down_bytes"] or 0) / 1e6 for r in daily], [(r["up_bytes"] or 0) / 1e6 for r in daily]]
        bc.categoryAxis.categoryNames = [r["day"][5:] for r in daily]
        bc.categoryAxis.labels.fontName = font
        bc.valueAxis.labels.fontName = font
        bc.valueAxis.valueMin = 0
        bc.bars[0].fillColor, bc.bars[1].fillColor = green, colors.HexColor("#3182F6")
        d.add(bc)
        d.add(String(30, 50 * mm, "MB (초록: 다운로드, 파랑: 업로드)", fontName=font, fontSize=7, fillColor=gray))
        story.append(d)
        story.append(table([["날짜", "패킷", "전체", "다운로드", "업로드"]] +
                           [[r["day"], f"{r['packets']:,}", terms.human_bytes(r["bytes"]), terms.human_bytes(r["down_bytes"]),
                             terms.human_bytes(r["up_bytes"])] for r in daily], [35 * mm, 30 * mm, 35 * mm, 35 * mm, 35 * mm]))
    else:
        story.append(Paragraph("이 기간에 저장된 사용량이 없어요.", body))

    story.append(Paragraph("프로토콜별 통신 비율", h2))
    if total:
        d = Drawing(170 * mm, 45 * mm)
        pie = Pie()
        pie.x, pie.y, pie.width, pie.height = 20, 5, 38 * mm, 38 * mm
        keys = [k for k in ("TCP", "UDP", "ICMP", "OTHER") if p.get(k)]
        pie.data = [p[k] for k in keys]
        pie.labels = [f"{k} {p[k] / total:.0%}" if p[k] / total >= 0.01 else "" for k in keys]
        pie.sideLabels = True
        pie.simpleLabels = False
        palette = [green, colors.HexColor("#3182F6"), colors.HexColor("#FF8A00"), gray]
        for i in range(len(keys)):
            pie.slices[i].fillColor = palette[i]
            pie.slices[i].fontName = font
        d.add(pie)
        story.append(d)

    def ip_table(rows, title):
        story.append(Paragraph(title, h2))
        if not rows:
            story.append(Paragraph("기록 없음 (패킷 보존 한도를 넘은 오래된 패킷은 집계되지 않아요)", body))
            return
        story.append(table([["IP", "패킷", "전송량"]] + [[r["ip"], f"{r['packets']:,}", terms.human_bytes(r["bytes"])] for r in rows],
                           [80 * mm, 40 * mm, 50 * mm]))
    ip_table(report.get("top_src"), "보내는 장치(출발지 IP)별 트래픽 Top 10")
    ip_table(report.get("top_dst"), "받는 장치(목적지 IP)별 트래픽 Top 10")

    story.append(Paragraph("포트(서비스)별 트래픽", h2))
    ports = report.get("ports") or []
    if ports:
        story.append(table([["프로토콜", "서비스", "패킷", "전송량"]] +
                           [[r["proto"], r["service"], f"{r['packets']:,}", terms.human_bytes(r["bytes"])] for r in ports],
                           [30 * mm, 60 * mm, 35 * mm, 45 * mm]))
    else:
        story.append(Paragraph("기록 없음", body))

    story.append(Paragraph("이상 탐지 이력", h2))
    if anoms:
        rows = [["탐지 시각", "종류", "위험", "관련 IP", "측정/기준", "상태"]]
        status_ko = {"active": "진행 중", "ended": "멈춤", "resolved": "조치 완료", "dismissed": "정상 처리"}
        for a in anoms[:60]:
            rows.append([_fmt_ts(a["detected_at"]), Paragraph(TYPE_LABELS.get(a["type"], a["type"]), body), SEVERITY_KO.get(a["severity"], a["severity"]),
                         a.get("src") or a.get("dst") or "-", f"{a.get('peak') or a.get('measured')}/{a.get('threshold')}",
                         status_ko.get(a["status"], a["status"])])
        story.append(table(rows, [32 * mm, 42 * mm, 14 * mm, 34 * mm, 28 * mm, 20 * mm]))
        if len(anoms) > 60:
            story.append(Paragraph(f"외 {len(anoms) - 60}건은 CSV 내보내기로 확인하세요.", small))
    else:
        story.append(Paragraph("이 기간에 탐지된 이상 징후가 없어요.", body))

    story += [Spacer(1, 6 * mm), Paragraph("본 리포트의 모든 수치는 NetCare가 실제로 캡처·측정한 데이터로 계산했어요. "
                                           "이상 징후는 '공격 확정'이 아니라 확인이 필요한 패턴이라는 뜻이에요.", small)]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="NetCare 네트워크 리포트", author="NetCare")
    doc.build(story)
    return buf.getvalue()
