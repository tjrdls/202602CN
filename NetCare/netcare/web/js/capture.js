/* 캡처 시작 모달(실시간·파일·테스트 데이터) */
import { S, $, $$, api, esc, toast, hooks } from "./core.js";
import { modal, closeModal } from "./ui.js";

export async function onCaptureBtn() {
  const st = S.status || {};
  if (["capturing", "importing", "testing"].includes(st.state)) {
    try { await api("/api/capture/stop", { method: "POST", body: {} }); toast("캡처를 멈췄어요"); hooks.tick(); } catch (e) { toast(e.message, true); }
    return;
  }
  openCaptureModal("live");
}
export async function openCaptureModal(tab) {
  const tabs = `<div class="seg source-tabs"><button data-t="live" class="${tab === "live" ? "on" : ""}">실시간 캡처</button><button data-t="file" class="${tab === "file" ? "on" : ""}">파일 분석</button><button data-t="test" class="${tab === "test" ? "on" : ""}">테스트 데이터</button></div>`;
  let body = "";
  if (tab === "live") {
    let ifs = [];
    try { ifs = (await api("/api/interfaces")).interfaces; } catch (e) { toast(e.message, true); }
    const cur = (S.status && S.status.config.interface) || (ifs.find((i) => i.is_default) || {}).name;
    const adminHint = S.status?.platform === "Windows" && !S.status?.is_admin
      ? `<div class="box box-gray">Windows 실시간 캡처는 Npcap과 관리자 권한이 필요해요. NetCare를 관리자 권한으로 다시 실행해 주세요.</div>` : "";
    body = `<p class="card-sub">어떤 네트워크를 살펴볼까요? 보통 <b>추천</b> 표시된 것을 고르면 돼요.</p>
      ${adminHint}<div class="iface-list">${ifs.map((i) => { const available = i.capture_available !== false; return `<label class="iface ${i.name === cur && available ? "sel" : ""}"><input type="radio" name="iface" value="${esc(i.name)}" ${i.name === cur && available ? "checked" : ""} ${available ? "" : "disabled"}>
        <div style="flex:1;min-width:0"><div class="if-name">${esc(i.description || i.name)} <span class="sub-ip">${esc(i.name)}</span> ${i.is_default ? `<span class="sev-badge s-good">추천</span>` : ""} ${!i.is_up ? `<span class="sev-badge s-info">꺼짐</span>` : ""} ${!available ? `<span class="sev-badge s-info">캡처 권한 필요</span>` : ""}</div>
        <div class="if-meta">${esc(i.ipv4.join(", ") || "IPv4 없음")}${i.mac ? " · " + esc(i.mac) : ""}</div></div></label>`; }).join("")}</div>
      <div class="form-row mt"><label>캡처 필터 (선택)</label><input class="input mono" id="bpf" placeholder="예: tcp port 443, udp, host 192.168.0.1" value="${esc((S.status && S.status.config.bpf_filter) || "")}">
        <div class="hint">비워 두면 모든 패킷을 수집해요. BPF 문법을 사용하며 잘못된 문법은 시작 전에 알려드려요.</div></div>
      <div class="box box-gray">🔒 내가 관리하는 네트워크에서만 사용해 주세요. NetCare는 패킷을 읽기만 하고, 사용자가 승인하지 않으면 아무 설정도 바꾸지 않아요.</div>
      <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">취소</button><button class="btn btn-primary" id="startLive">캡처 시작</button></div>`;
  } else if (tab === "file") {
    body = `<p class="card-sub">Wireshark·tcpdump로 저장한 pcap/pcapng 파일을 분석해요. 관리자 권한이 없어도 돼요.</p>
      <div class="file-drop" id="drop">📂 여기를 눌러 파일을 선택하세요<br><span class="sub-ip">최대 500MB · .pcap .pcapng .cap</span></div>
      <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">닫기</button></div>`;
  } else {
    let sc = [];
    try { sc = (await api("/api/test/scenarios")).scenarios; } catch (e) { toast(e.message, true); }
    body = `<div class="box box-sim" style="margin-top:0">🧪 <b>테스트 데이터란?</b>프로그램이 메모리에서 만든 가상 패킷이에요. 실제 네트워크로 전송되지 않고, 화면에 항상 ‘테스트 데이터’로 표시되며 리포트에서는 기본적으로 빠져요. 문서·예제용으로 예약된 IP 주소만 사용해요.</div>
      <div style="margin-top:12px">${sc.map((s, i) => `<div class="scenario ${i === 0 ? "sel" : ""}" data-sc="${esc(s.id)}"><div class="sc-t">${esc(s.title)}</div><div class="sc-d">${esc(s.desc)} · 약 ${s.duration}초</div></div>`).join("")}</div>
      <div class="modal-actions"><button class="btn btn-secondary" onclick="App.closeModal()">취소</button><button class="btn btn-sim" id="startTest">테스트 재생</button></div>`;
  }
  modal(`<h3>네트워크 살펴보기</h3>${tabs}${body}`, false);
  $$(".source-tabs button").forEach((b) => b.onclick = () => openCaptureModal(b.dataset.t));
  $$(".iface").forEach((l) => l.onclick = () => { if (l.querySelector("input")?.disabled) return; $$(".iface").forEach((x) => x.classList.remove("sel")); l.classList.add("sel"); });
  const sl = $("#startLive");
  if (sl) sl.onclick = async () => {
    const iface = ($("input[name=iface]:checked") || {}).value;
    sl.disabled = true; sl.textContent = "시작하는 중…";
    try { await api("/api/capture/start", { method: "POST", body: { iface, bpf_filter: $("#bpf").value } }); closeModal(); toast("실시간 캡처를 시작했어요"); hooks.tick(); }
    catch (e) {
      sl.disabled = false; sl.textContent = "캡처 시작";
      const box = document.createElement("div"); box.className = "box box-red"; box.innerHTML = `<b>${esc(e.message)}</b>${esc(e.help || "")}`;
      $("#modalCard .modal-actions").before(box);
    }
  };
  const drop = $("#drop");
  if (drop) drop.onclick = () => $("#pcapInput").click();
  $$(".scenario").forEach((s) => s.onclick = () => { $$(".scenario").forEach((x) => x.classList.remove("sel")); s.classList.add("sel"); });
  const stt = $("#startTest");
  if (stt) stt.onclick = async () => {
    const sc = ($(".scenario.sel") || {}).dataset?.sc;
    try { await api("/api/test/run", { method: "POST", body: { scenario: sc } }); closeModal(); toast("테스트 데이터를 재생해요"); hooks.go("home"); hooks.tick(); } catch (e) { toast(e.message, true); }
  };
}
export async function uploadPcap(file) {
  const fd = new FormData(); fd.append("file", file);
  closeModal(); toast(`${file.name} 분석을 시작해요`);
  try { await api("/api/capture/import", { method: "POST", body: fd }); hooks.go("home"); hooks.tick(); } catch (e) { toast(e.message, true); }
}
