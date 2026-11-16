/* 설정 모달 */
import { $, $$, api, esc, toast } from "./core.js";
import { modal, closeModal } from "./ui.js";
import { themePref, setThemePref } from "./theme.js";
import { invalidateRules } from "./rules.js";

const DET_FIELDS = [
  ["window_sec", "탐지 윈도우(초)", "최근 몇 초를 묶어서 판단할지"], ["ip_pps_threshold", "① 장치별 초당 패킷 기준", "한 IP가 1초에 보내는 패킷 수"],
  ["syn_threshold", "② 새 연결 요청(SYN) 기준", "윈도우 동안의 SYN 개수"], ["syn_success_ratio_max", "② 연결 완료율 기준(0~1)", "이보다 낮으면 의심 (0.3 = 30%)"],
  ["port_share_threshold", "③ 포트 집중 비율(0~1)", "한 포트가 차지하는 비율"], ["port_min_packets", "③ 포트 집중 최소 패킷", "윈도우 내 최소 패킷 수"],
  ["traffic_z_threshold", "④ 급증 z-score 기준", "평소 대비 표준편차 몇 배"], ["traffic_static_bps", "④ 학습 전 고정 기준(바이트/초)", "10000000 = 약 80Mbps"],
  ["warmup_sec", "④ 기준선 학습 시간(초)", "이 시간 동안 평소 사용량을 학습"], ["repeat_conn_threshold", "⑤ 반복 연결 기준", "같은 목적지·포트 SYN 횟수"],
  ["port_scan_threshold", "⑤ 포트 스캔 기준", "서로 다른 목적지·포트 수"], ["dns_failure_threshold", "DNS 실패 기준(건)", "오류+무응답 건수"],
  ["cooldown_sec", "같은 알림 묶음 시간(초)", "이 시간 안에 다시 나오면 기존 알림을 갱신"],
];
export async function openSettings() {
  let c;
  try { c = await api("/api/settings"); } catch (e) { toast(e.message, true); return; }
  const d = c.detection, p = c.probe, th = themePref();
  modal(`<h3>설정</h3><p class="card-sub">기본값은 일반 가정·사무실 네트워크를 기준으로 정했어요. 오탐이 많으면 기준을 높이세요.</p>
    <div class="settings-section"><h4>화면</h4>
      <div class="form-row"><label>테마</label><div class="seg" id="thSeg"><button data-v="auto" class="${th === "auto" ? "on" : ""}">시스템 설정</button><button data-v="light" class="${th === "light" ? "on" : ""}">라이트</button><button data-v="dark" class="${th === "dark" ? "on" : ""}">다크</button></div>
        <div class="hint">바로 적용돼요. 상단의 ☾ 버튼으로도 바꿀 수 있어요.</div></div>
      <label class="switch"><span>시작할 때 전문가 모드</span><input type="checkbox" id="expDef" ${c.expert_mode_default ? "checked" : ""}></label></div>
    <div class="settings-section"><h4>탐지 기준</h4><div class="form-grid">${DET_FIELDS.map(([k, l, h]) => `<div class="form-row"><label>${l}</label><input class="input" data-det="${k}" type="number" step="any" value="${esc(d[k])}"><div class="hint">${h}</div></div>`).join("")}</div>
      <div class="form-row"><label>화이트리스트 (탐지·차단 제외)</label><textarea class="input mono" id="wl" rows="3" placeholder="한 줄에 하나씩, IP 또는 CIDR (예: 192.168.0.0/24)">${esc(d.whitelist.join("\n"))}</textarea></div></div>
    <div class="settings-section"><h4>연결 점검</h4><div class="form-grid">
      <div class="form-row"><label>외부 점검 대상</label><input class="input" id="pExt" value="${esc(p.external_target)}"></div>
      <div class="form-row"><label>점검 간격(초)</label><input class="input" id="pInt" type="number" value="${esc(p.interval_sec)}"></div></div>
      <div class="form-row"><label>DNS 테스트 도메인</label><input class="input" id="pDns" value="${esc(p.dns_test_domains.join(", "))}"></div>
      <label class="switch"><span>주기적 연결 점검(ping·DNS) 사용</span><input type="checkbox" id="pEn" ${p.enabled ? "checked" : ""}></label></div>
    <div class="settings-section"><h4>저장</h4><div class="form-grid">
      <div class="form-row"><label>보관할 최대 패킷 수</label><input class="input" id="maxPk" type="number" value="${esc(c.max_db_packets)}"><div class="hint">넘으면 오래된 패킷부터 지워요 (사용량 집계는 유지)</div></div>
      <div class="form-row"><label>원본 저장 크기(바이트)</label><input class="input" id="snap" type="number" value="${esc(c.raw_snaplen)}"><div class="hint">상세 헤더 분석용</div></div></div>
      <label class="switch"><span>상세 분석용 원본 바이트 저장</span><input type="checkbox" id="raw" ${c.store_raw ? "checked" : ""}></label></div>
    <div class="settings-section"><h4>자동 차단</h4>
      <label class="switch"><span>위험 징후 발생 시 자동으로 방화벽 차단<br><span class="sub-ip">기본값: 꺼짐 · 외부 공인 IP의 ‘위험’ 등급 SYN 급증·포트 스캔·단방향 폭주만 대상 · NetCare가 관리자 권한으로 실행 중일 때만 동작 · ${esc(c.auto_block_ttl_min)}분 뒤 자동 해제</span></span>
        <input type="checkbox" id="ab" ${c.auto_block_enabled ? "checked" : ""}></label>
      <div id="abWarn" class="${c.auto_block_enabled ? "hidden" : ""}"><div class="box box-warn hidden" id="abBox"><b>정말 켤까요?</b>자동 차단은 오탐일 때 정상 통신을 끊을 수 있어요. 차단 기록은 ‘조치 기록’에 남고 언제든 되돌릴 수 있어요.
        <label class="check"><input type="checkbox" id="abConsent"> 위험을 이해했고 자동 차단을 켜는 데 동의해요.</label></div></div></div>
    <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">취소</button><button class="btn btn-primary" id="saveSet">저장</button></div>`, true);
  $$("#thSeg button").forEach((b) => b.onclick = () => { $$("#thSeg button").forEach((x) => x.classList.toggle("on", x === b)); setThemePref(b.dataset.v); });
  const ab = $("#ab");
  ab.onchange = () => $("#abBox").classList.toggle("hidden", !(ab.checked && !c.auto_block_enabled));
  $("#saveSet").onclick = async () => {
    const det = {};
    $$("[data-det]").forEach((i) => det[i.dataset.det] = Number(i.value));
    det.whitelist = $("#wl").value.split(/\n|,/).map((s) => s.trim()).filter(Boolean);
    const body = { detection: det, max_db_packets: Number($("#maxPk").value), raw_snaplen: Number($("#snap").value), store_raw: $("#raw").checked,
      auto_block_enabled: ab.checked, auto_block_consent: !!($("#abConsent") && $("#abConsent").checked), expert_mode_default: $("#expDef").checked,
      probe: { external_target: $("#pExt").value.trim(), interval_sec: Number($("#pInt").value), enabled: $("#pEn").checked,
        dns_test_domains: $("#pDns").value.split(",").map((s) => s.trim()).filter(Boolean) } };
    try { await api("/api/settings", { method: "PUT", body }); invalidateRules(); closeModal(); toast("설정을 저장했어요"); } catch (e) { toast(e.message, true); }
  };
}
