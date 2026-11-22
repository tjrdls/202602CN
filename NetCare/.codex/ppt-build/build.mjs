import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = path.resolve('NetCare');
const build = path.join(root, '.codex', 'ppt-build');
const outputDir = path.join(root, 'output');
const finalPath = path.join(outputDir, 'NetCare_발표자료_최종.pptx');
const W = 1280, H = 720;
const C = { ink:'#13263D', muted:'#587087', blue:'#1769AA', teal:'#00A6A6', pale:'#EAF4FA', pale2:'#F3F8FB', line:'#D7E3EB', white:'#FFFFFF', green:'#18866B', amber:'#B96B12', red:'#B44747', navy:'#0B1C2D' };
const font = 'Malgun Gothic';
await fs.mkdir(build, { recursive:true });
await fs.mkdir(outputDir, { recursive:true });
const nm = 'C:/Program Files/WindowsApps/OpenAI.CodexPrimaryRuntime.v26-1112-737-0_26.1112.737.0_x64__3k8sg7r9htsxt/dependencies/node/node_modules';
process.env.RUNTIME_NODE_MODULES=nm;
const { Presentation, PresentationFile } = await import(pathToFileURL(path.join(nm, '@oai/artifact-tool/dist/artifact_tool.mjs')).href);
const p = Presentation.create({ slideSize:{width:W,height:H} });

function txt(s, text, x,y,w,h, size=24, color=C.ink, bold=false, opts={}) {
  const sh=s.shapes.add({geometry:'textbox',name:opts.name||text.slice(0,40),position:{left:x,top:y,width:w,height:h},fill:'none',line:{style:'solid',fill:'none',width:0}});
  sh.text=text;
  sh.text.style={typeface:font,fontSize:size,color,bold,verticalAlignment:opts.valign||'middle',wrap:true,alignment:opts.align||'left',...opts.style};
  return sh;
}
function rect(s,x,y,w,h,fill,stroke='none',radius=0){
 return s.shapes.add({geometry:radius?'roundRect':'rect',position:{left:x,top:y,width:w,height:h},fill,line:{style:'solid',fill:stroke,width:stroke==='none'?0:1},...(radius?{borderRadius:'rounded-xl'}:{})});
}
function base(title, kicker='NETCARE'){
 const s=p.slides.add(); s.background.fill=C.white;
 rect(s,0,0,12,H,C.teal); txt(s,kicker.toUpperCase(),64,36,320,24,14,C.teal,true);
 txt(s,title,64,74,1152,62,36,C.ink,true);
 rect(s,64,147,1152,2,C.line); return s;
}
function bullet(s, lines, x,y,w, size=22, gap=62, color=C.ink){
 lines.forEach((v,i)=>{rect(s,x,y+i*gap+12,8,8,C.teal,'none',1);txt(s,v,x+24,y+i*gap,w-24,gap-6,size,color,false);});
}
async function image(s, rel, x,y,w,h,alt){
 const file=path.join(root,rel); const bytes=await fs.readFile(file);
 s.images.add({blob:bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),contentType:'image/png',alt,fit:'contain',position:{left:x,top:y,width:w,height:h}});
}
function note(s, text){s.speakerNotes.text=text;}
function node(s,x,y,w,h,label,accent=C.blue){rect(s,x,y,w,h,C.pale2,C.line,1);rect(s,x,y,6,h,accent);txt(s,label,x+16,y+6,w-28,h-12,20,C.ink,true,{align:'center'});}

// 1 — title
{
 const s=p.slides.add(); s.background.fill=C.navy;
 rect(s,0,0,16,H,C.teal);
 txt(s,'NetCare',86,126,570,96,62,C.white,true);
 txt(s,'패킷 이상을 이해하고\n안전하게 해결하는 네트워크 진단 도구',90,242,680,130,34,'#D9EAF3',false);
 rect(s,90,420,100,5,C.teal);
 txt(s,'탐지 근거부터 사용자 승인, 효과 확인까지',90,450,700,48,23,C.white,false);
 txt(s,'컴퓨터 네트워크 프로젝트',90,620,470,28,17,'#9BB5C8',false);
 // editable packet motif
 for(let i=0;i<5;i++){rect(s,820+i*58,250+i%2*34,38,38,i%2?C.blue:C.teal,'none',1);}
 rect(s,805,342,350,3,'#587087'); txt(s,'CAPTURE  →  EXPLAIN  →  VERIFY',806,365,400,28,16,'#9BB5C8',true);
 note(s,'발표 구성은 NetCare/docs/03_발표자료.md와 NetCare/README.md를 바탕으로 작성.');
}
// 2 — problem
{
 const s=base('패킷은 많지만, 원인과 다음 행동은 어렵다','문제와 목표');
 txt(s,'네트워크 문제를 처음 접하는 사용자에게 필요한 것은 경고 한 줄이 아닙니다.',80,185,1080,56,26,C.ink,true);
 const cols=[['정보 과잉','전문 용어와 긴 패킷 목록'],['판단 부담','정상 신호와 이상 징후 구분'],['조치 불안','원인·영향을 모른 채 설정 변경']];
 cols.forEach((a,i)=>{let x=82+i*380;txt(s,a[0],x,300,300,38,25,i===2?C.amber:C.blue,true);rect(s,x,349,300,2,C.line);txt(s,a[1],x,370,310,86,21,C.muted);});
 rect(s,80,520,1090,86,C.pale,'none',1);txt(s,'목표',104,535,80,44,20,C.teal,true);txt(s,'탐지 → 원인 설명 → 사용자 승인 → 조치 → 효과 확인·되돌리기',205,532,920,54,23,C.ink,true);
 note(s,'문제 정의와 제품 목표.');
}
// 3 — end-to-end
{
 const s=base('분석에서 복구 확인까지 한 흐름으로','사용자 흐름');
 const labels=[['수집','실시간·파일·합성'],['분석','패킷·통계·규칙'],['설명','원인·영향·불확실성'],['승인','영향을 확인'],['조치','사용자 승인 후 실행'],['확인','효과·되돌리기']];
 labels.forEach((a,i)=>{let x=65+i*198;rect(s,x,270,168,148,i===5?'#E8F6F2':C.pale2,C.line,1);txt(s,a[0],x+12,288,144,42,23,i===5?C.green:C.blue,true,{align:'center'});txt(s,a[1],x+10,340,148,54,16,C.muted,false,{align:'center'});if(i<5)txt(s,'→',x+168,317,30,38,22,C.teal,true,{align:'center'});});
 txt(s,'시스템을 바꾸는 조치는 미리보기와 승인 뒤 실행하고, 결과를 다시 측정합니다.',90,490,1100,48,22,C.ink,false,{align:'center'});
 note(s,'승인 기반 조치의 사용자 흐름.');
}
// 4 — architecture
{
 const s=base('수집과 처리를 분리해 패킷을 분석한다','시스템 구조');
 node(s,72,247,188,98,'네트워크 인터페이스'); txt(s,'→',263,275,36,38,26,C.teal,true,{align:'center'});
 node(s,302,247,184,98,'Scapy 캡처',C.teal); txt(s,'→',489,275,36,38,26,C.teal,true,{align:'center'});
 node(s,528,247,184,98,'제한 큐',C.amber); txt(s,'→',715,275,36,38,26,C.teal,true,{align:'center'});
 node(s,754,247,184,98,'파싱·통계·탐지'); txt(s,'→',941,275,36,38,26,C.teal,true,{align:'center'});
 node(s,980,247,222,98,'SQLite · 웹 UI',C.green);
 txt(s,'Npcap / BPF / AF_PACKET',305,366,182,44,15,C.muted,false,{align:'center'});
 txt(s,'큐 초과분도 버린 패킷 수로 표시',517,376,213,42,16,C.amber,true,{align:'center'});
 rect(s,85,496,1110,92,C.pale2,'none',1);txt(s,'입력 방식',110,513,130,34,18,C.teal,true);txt(s,'실시간 캡처 · pcap 파일 · 합성 테스트 데이터',260,505,860,48,22,C.ink,false);
 note(s,'README.md의 동작 원리와 시스템 구성 요약. 캡처 계층은 OS에 따라 달라짐.');
}
// 5 — capture stack
{
 const s=base('Scapy가 패킷을 다루고, Npcap이 Windows에서 프레임을 전달한다','Windows 캡처');
 txt(s,'NetCare',95,225,210,42,24,C.blue,true,{align:'center'});txt(s,'→',312,225,58,42,25,C.teal,true,{align:'center'});
 txt(s,'Scapy',375,225,180,42,24,C.blue,true,{align:'center'});txt(s,'→',565,225,58,42,25,C.teal,true,{align:'center'});
 txt(s,'Npcap 드라이버',630,225,260,42,24,C.blue,true,{align:'center'});txt(s,'→',900,225,58,42,25,C.teal,true,{align:'center'});
 txt(s,'이더넷 어댑터',966,225,230,42,24,C.blue,true,{align:'center'});
 rect(s,85,299,1100,2,C.line);
 bullet(s,['Scapy는 캡처·패킷 해석을 요청하는 Python 라이브러리다.','Npcap은 Windows 네트워크 드라이버로, 실제 인터페이스의 패킷 접근을 제공한다.','따라서 Windows 실시간 캡처에는 Npcap 설치와 관리자 권한이 필요할 수 있다.'],105,344,1050,20,66);
 rect(s,85,565,1100,56,C.pale,'none',1);txt(s,'확인한 환경: Windows 관리자 권한 · Npcap Ethernet · 시작/정지 및 패킷 수신',105,574,1045,38,19,C.ink,true);
 note(s,'Windows에서 캡처 계층이 macOS BPF, Linux AF_PACKET과 다른 이유를 설명.');
}
// 6 — detection
{
 const s=base('패킷 수만 보지 않고 연결 맥락을 함께 본다','탐지와 오탐 완화');
 txt(s,'규칙 기반 조건',92,207,460,34,20,C.blue,true);txt(s,'통계 기준선',700,207,460,34,20,C.teal,true);
 rect(s,92,258,470,210,C.pale2,C.line,1);txt(s,'SYN Flood',120,283,400,36,25,C.ink,true);txt(s,'SYN 개수만 세지 않고\n연결 시작 측의 마지막 ACK까지 추적',120,335,400,82,21,C.muted);
 rect(s,700,258,470,210,C.pale2,C.line,1);txt(s,'트래픽 급증',728,283,400,36,25,C.ink,true);txt(s,'평소 사용량을 EWMA로 학습하고\nz-score가 기준을 넘는지 평가',728,335,400,82,21,C.muted);
 txt(s,'완료된 핸드셰이크 · 양방향 다운로드 · HTTPS 등 일반 포트 · DNS 부분 응답을 오탐 완화에 반영',95,524,1080,56,19,C.ink,false,{align:'center'});
 note(s,'탐지 동작과 오탐 완화는 프로젝트 문서의 구현 설명을 요약.');
}
// 7 — evidence case
{
 const s=base('실제 다운로드를 공격으로 단정하지 않도록 보정했다','실측에서 발견한 문제');
 txt(s,'실측에서 처음 드러난 현상',92,205,430,34,19,C.muted,true);
 txt(s,'약 89 MB',92,260,340,62,42,C.blue,true);txt(s,'15초 다운로드',92,325,340,34,21,C.ink);
 txt(s,'처음에는 과다 패킷을 위험으로 분류',92,390,470,64,22,C.red,true);
 rect(s,610,220,2,320,C.line);
 txt(s,'패킷 맥락을 반영해 수정',665,205,470,34,19,C.muted,true);
 bullet(s,['역방향 ACK 비율 0.19 → 양방향 통신 판정','정상 다운로드의 과다 패킷 등급을 낮춤','급증은 EWMA z-score 7.51로 별도 탐지'],665,268,510,19,70);
 rect(s,665,505,480,72,'#E8F6F2','none',1);txt(s,'정상 다운로드가 위험으로 표시되지 않음',684,518,440,44,20,C.green,true,{align:'center'});
 note(s,'macOS 실측 기록: 66초 기준선 학습, 89MB 파일 15초 다운로드. 해당 시점 기록 기준.');
}
// 8 — safety
{
 const s=base('조치 전 영향을 알리고, 승인 뒤 효과를 확인한다','진단과 안전');
 const steps=[['근거','무엇을 관찰했는지'],['영향','예상 효과·부작용'],['승인','사용자가 직접 확인'],['검증','같은 지표 재측정'],['복구','NetCare 규칙 롤백']];
 steps.forEach((a,i)=>{const x=78+i*230;txt(s,String(i+1).padStart(2,'0'),x,235,52,30,16,C.teal,true);txt(s,a[0],x,278,190,42,25,C.ink,true);txt(s,a[1],x,334,198,60,18,C.muted);if(i<4)txt(s,'→',x+189,282,38,38,22,C.teal,true,{align:'center'});});
 rect(s,90,465,1080,106,C.pale,'none',1);txt(s,'기본 원칙',116,479,130,34,18,C.blue,true);txt(s,'자동 차단은 기본 꺼짐 · 보호 IP 차단 거부 · 테스트/실험실은 실제 OS 방화벽을 변경하지 않음',265,470,870,82,20,C.ink,true);
 note(s,'README 안전장치 요약. 실제 방화벽 적용과 롤백은 현재 Windows에서 검증되지 않음.');
}
// 9 — UI
{
 const s=base('한 화면에서 상태를 보고, 필요한 분석으로 들어간다','제품 화면');
 await image(s,'docs/screenshots/e2e_home_test.png',70,188,740,414,'NetCare 홈 대시보드 테스트 화면');
 txt(s,'홈',865,205,300,32,19,C.teal,true);txt(s,'상태 요약과\n최근 탐지',865,245,330,78,24,C.ink,true);
 rect(s,865,354,290,2,C.line);txt(s,'패킷 분석',865,380,300,32,19,C.teal,true);txt(s,'쉬운 설명과\n전문가 상세 보기',865,420,330,78,23,C.ink,true);
 note(s,'합성·테스트 데이터로 촬영한 README 화면 캡처. 실제 사용자 트래픽을 보여 주는 화면은 아님.');
}
// 10 — diagnosis UI
{
 const s=base('경고에 근거와 다음 행동을 함께 제시한다','문제 해결');
 await image(s,'docs/screenshots/e2e_issue_v2.png',70,188,740,414,'NetCare 문제 해결 상세 테스트 화면');
 bullet(s,['탐지 이유와 측정값','영향과 오탐 가능성','관련 조치와 승인 상태'],858,245,325,20,76);
 note(s,'합성·테스트 데이터로 촬영한 문제 해결 화면. 화면은 현재 UI를 보여 주기 위한 것으로 실제 공격 사례가 아님.');
}
// 11 — lab compact
{
 const s=base('실험실은 탐지 동작을 반복 검증하는 보조 도구다','가상 실험실');
 txt(s,'실제 네트워크와 분리',90,216,420,42,25,C.blue,true);
 txt(s,'12개 시나리오',90,280,400,44,24,C.ink,true);txt(s,'강도·시드·실행 시간을 바꿔 재현',90,328,450,38,19,C.muted);
 txt(s,'정답과 비교',90,402,400,44,24,C.teal,true);txt(s,'Precision · Recall · F1 · FPR · 탐지 시간',90,450,470,38,19,C.muted);
 await image(s,'docs/screenshots/e2e_lab_result.png',620,202,580,340,'NetCare 가상 실험실 결과 화면');
 rect(s,620,562,580,50,'#FFF4E6','none',1);txt(s,'수치는 합성 시나리오 결과이며 실제 성능 보증이 아님',638,568,542,34,17,C.amber,true,{align:'center'});
 note(s,'가상 실험실의 역할만 간단히 설명. 최신 규칙 이전 측정한 156회 벤치마크 수치는 본 발표에서 대표 성능처럼 제시하지 않음.');
}
// 12 — validation
{
 const s=base('Windows에서 실제 이더넷 캡처와 UI 흐름을 확인했다','검증');
 txt(s,'실제 Windows 캡처',92,205,500,36,20,C.blue,true);
 txt(s,'90,316',92,258,380,74,49,C.ink,true);txt(s,'패킷 처리 · 누락 0건',95,336,450,38,20,C.muted);
 txt(s,'Npcap Ethernet · 관리자 권한',95,396,450,32,18,C.muted);
 rect(s,630,205,2,345,C.line);
 txt(s,'자동화 검증',688,205,430,36,20,C.teal,true);
 txt(s,'71 / 71',688,265,390,56,37,C.ink,true);txt(s,'Windows Chrome UI E2E',688,321,410,34,19,C.muted);
 txt(s,'55 / 55',688,388,390,56,37,C.ink,true);txt(s,'API 제외 pytest',688,444,410,34,19,C.muted);
 rect(s,92,522,1095,72,'#FFF4E6','none',1);txt(s,'Windows API pytest는 TestClient 초기화 단계에서 완료하지 못함. 실제 HTTP API는 별도로 확인.',112,530,1055,54,18,C.amber,true);
 note(s,'2026-11-17 Windows 실제 확인. 90,316은 관찰 시점 누적치이며 지속 처리량 지표가 아님. Windows API pytest는 TestClient 초기화 문제로 완료하지 못했고, API는 실제 서버에서 별도 확인.');
}
// 13 — limits / close
{
 const s=base('확인한 범위와 남은 검증 과제','한계와 다음 단계');
 txt(s,'이번에 확인',90,208,440,34,20,C.green,true);
 bullet(s,['Windows Npcap 이더넷 캡처','캡처 시작·정지와 패킷 수신','Windows UI E2E 및 API 제외 테스트'],90,258,480,19,62);
 txt(s,'남은 검증',665,208,440,34,20,C.amber,true);
 bullet(s,['Windows 방화벽 적용·롤백','Linux 실기기 캡처','장시간 연속 운용','최신 규칙 기준 실험실 재측정'],665,258,505,19,62,C.ink);
 rect(s,90,520,1090,78,C.navy,'none',1);txt(s,'NetCare의 핵심은 경고가 아니라, 근거를 이해하고 안전하게 복구하는 과정입니다.',112,532,1040,52,22,C.white,true,{align:'center'});
 note(s,'미검증 항목을 구분해 마무리. 실험실은 보조적 검증 수단이라는 점을 강조.');
}

// Private draft, previews, then skill finalizer.
for (const [i, slide] of p.slides.items.entries()) {
 const png=await p.export({slide,format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await png.arrayBuffer()));
}
const montage=await p.export({format:'png',montage:true});
await fs.writeFile(path.join(build,'montage.png'),new Uint8Array(await montage.arrayBuffer()));
const staging=path.join(root,'.codex-finalizer'); await fs.mkdir(staging,{recursive:true});
const candidate=path.join(staging,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidate);
const skill='C:/Users/l22s2/.codex/plugins/cache/openai-primary-runtime/presentations/26.1112.11217/skills/presentations';
const {finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')).href);
const runtimePython='C:/Program Files/WindowsApps/OpenAI.CodexPrimaryRuntime.v26-1112-737-0_26.1112.737.0_x64__3k8sg7r9htsxt/dependencies/python/python.exe';
const result=await finalizePresentation({workspaceDir:root,candidatePath:candidate,finalPath,pythonExecutable:runtimePython,integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit'],requiredNativeTableOwnerSlides:[],fontPolicy:{basis:'design',families:[font]},verifyArtifactToolImport:true,receiptPath:path.join(staging,'NetCare_발표자료.validation.json')});
console.log(JSON.stringify({finalPath,slideCount:p.slides.items.length,result},null,2));
