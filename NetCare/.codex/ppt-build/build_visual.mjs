import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const nm='C:/Program Files/WindowsApps/OpenAI.CodexPrimaryRuntime.v26-1112-737-0_26.1112.737.0_x64__3k8sg7r9htsxt/dependencies/node/node_modules';
process.env.RUNTIME_NODE_MODULES=nm;
const {Presentation,PresentationFile}=await import(pathToFileURL(path.join(nm,'@oai/artifact-tool/dist/artifact_tool.mjs')).href);
const root=path.resolve('NetCare'), build=path.join(root,'.codex','ppt-build'), outDir=path.join(root,'output');
const finalPath=path.join(outDir,'NetCare_발표자료_시각개선.pptx');
await fs.mkdir(build,{recursive:true}); await fs.mkdir(outDir,{recursive:true});
const W=1280,H=720,F='Malgun Gothic';
const K={navy:'#101F35',ink:'#162B45',body:'#344F68',muted:'#657D92',blue:'#2169C4',teal:'#00A8A1',aqua:'#DDF5F1',pale:'#EEF5FA',paper:'#F8FAFC',line:'#D8E3EB',white:'#FFFFFF',amber:'#E7952F',amberP:'#FFF1DE',red:'#D94D55',green:'#16866E',greenP:'#E4F6EF',violet:'#7559C8'};
const p=Presentation.create({slideSize:{width:W,height:H}});
function rect(s,x,y,w,h,fill,stroke='none',r=false){return s.shapes.add({geometry:r?'roundRect':'rect',position:{left:x,top:y,width:w,height:h},fill,line:{style:'solid',fill:stroke,width:stroke==='none'?0:1},...(r?{borderRadius:'rounded-xl'}:{})});}
function line(s,x1,y1,x2,y2,color=K.line,width=2){
 if(y1===y2)return rect(s,Math.min(x1,x2),y1-width/2,Math.max(Math.abs(x2-x1),width),width,color);
 if(x1===x2)return rect(s,x1-width/2,Math.min(y1,y2),width,Math.max(Math.abs(y2-y1),width),color);
 rect(s,Math.min(x1,x2),y1-width/2,Math.max(Math.abs(x2-x1),width),width,color);
 rect(s,x2-width/2,Math.min(y1,y2),width,Math.max(Math.abs(y2-y1),width),color);
}
function text(s,t,x,y,w,h,size=22,color=K.ink,bold=false,align='left',opts={}){const a=s.shapes.add({geometry:'textbox',name:opts.name||t.slice(0,28),position:{left:x,top:y,width:w,height:h},fill:'none',line:{style:'solid',fill:'none',width:0}});a.text=t;a.text.style={typeface:F,fontSize:size,color,bold,alignment:align,verticalAlignment:opts.valign||'middle',wrap:true,...(opts.style||{})};return a;}
function base(title,section,accent=K.teal){const s=p.slides.add();s.background.fill=K.paper;rect(s,0,0,12,H,accent);text(s,section.toUpperCase(),64,32,500,24,14,accent,true);text(s,title,64,68,1152,64,36,K.ink,true);line(s,64,145,1216,145,K.line,2);return s;}
function note(s,t){s.speakerNotes.text=t;}
function dot(s,x,y,r,color){rect(s,x-r,y-r,r*2,r*2,color,'none',true);}
function bullet(s,t,x,y,w,sz=20,color=K.ink){dot(s,x+4,y+22,4,K.teal);text(s,t,x+22,y,w-22,46,sz,color);}
function pill(s,t,x,y,w,color=K.blue,fill=K.pale){rect(s,x,y,w,30,fill,'none',true);text(s,t,x+8,y+2,w-16,25,14,color,true,'center');}
async function pic(s,rel,x,y,w,h,alt){const b=await fs.readFile(path.join(root,rel));s.images.add({blob:b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength),contentType:'image/png',alt,fit:'contain',position:{left:x,top:y,width:w,height:h}});}
function node(s,x,y,w,h,title,sub,color=K.blue){rect(s,x,y,w,h,K.white,K.line,true);rect(s,x,y,7,h,color);text(s,title,x+20,y+15,w-34,34,22,K.ink,true);text(s,sub,x+20,y+54,w-36,h-63,16,K.muted);}

// Cover: expressive but fully editable network motif.
{
 const s=p.slides.add();s.background.fill=K.navy;rect(s,0,0,16,H,K.teal);
 text(s,'NetCare',78,110,590,88,64,K.white,true);
 text(s,'패킷 이상을 이해하고\n안전하게 해결하는 네트워크 진단 도구',82,218,665,122,34,'#D9EAF7');
 text(s,'탐지 근거를 설명하고, 승인된 조치의 효과까지 확인합니다',84,390,680,52,22,'#B6CBDC');
 // network path drawing
 const pts=[[880,170],[1040,220],[930,320],[1110,385],[850,460],[1050,540]];
 [[0,1],[0,2],[1,2],[1,3],[2,3],[2,4],[3,5],[4,5]].forEach(([a,b],i)=>line(s,...pts[a],...pts[b],i%2?K.blue:K.teal,3));
 pts.forEach((q,i)=>dot(s,q[0],q[1],i===2?19:13,i===2?K.amber:(i%2?K.blue:K.teal)));
 text(s,'패킷 → 맥락 → 설명 → 승인 → 검증',800,610,390,28,16,'#ABC3D5',true,'center');
 note(s,'출처: NetCare/docs/03_발표자료.md, README.md.');
}
// Problem as a transformation, not a text list.
{
 const s=base('패킷 목록은 원인을 바로 알려주지 않는다','문제와 목표',K.blue);
 text(s,'한 번의 네트워크 문제도 화면에는 수많은 조각으로 보입니다',82,174,1080,40,23,K.body);
 const x0=86,y0=250;
 for(let i=0;i<10;i++){const yy=y0+i*23;rect(s,x0,yy,218,16,i%3===0?'#E6EDF4':'#D7E2EA','none',true);text(s,['TCP','DNS','TLS','TCP','UDP'][i%5],x0+8,yy-1,50,16,10,K.muted,true);}
 text(s,'패킷 목록 예시 · 주소 · 포트 · 플래그 · 시간',86,500,360,28,14,K.muted);
 // transform arrow
 line(s,350,355,505,355,K.teal,6);text(s,'맥락화',372,312,110,30,17,K.teal,true,'center');
 // result reveals three answers
 text(s,'NetCare가 정리하는 것',562,224,600,38,20,K.teal,true);
 const answers=[['무슨 일인가','이상 징후와 관찰된 값',K.blue],['왜 의심하는가','기준·연결 상태·예외',K.violet],['무엇을 할까','영향을 알고 승인 후 조치',K.amber]];
 answers.forEach((a,i)=>{const yy=288+i*88;rect(s,562,yy,564,66,K.white,K.line,true);rect(s,562,yy,8,66,a[2]);text(s,a[0],584,yy+8,175,48,21,a[2],true);text(s,a[1],776,yy+8,330,48,19,K.body);});
 text(s,'목표: 경보 하나가 아니라, 이해와 복구까지 이어지는 흐름',120,610,1050,36,22,K.ink,true,'center');
 note(s,'초보자의 부담과 제품 목표를 시각적으로 대비.');
}
// Main flow: large connected path.
{
 const s=base('탐지부터 복구 확인까지 이어진다','사용자 흐름',K.teal);
 const steps=[['01','수집','실시간 · 파일 · 합성'],['02','분석','패킷 · 통계 · 규칙'],['03','설명','원인 · 영향 · 불확실성'],['04','승인','실행 전 영향 확인'],['05','조치','사용자가 허용한 변경'],['06','검증','효과 확인 · 되돌리기']];
 steps.forEach((a,i)=>{const x=55+i*190;dot(s,x+50,272,27,i===5?K.green:(i===3?K.amber:K.blue));text(s,a[0],x+24,254,52,34,14,K.white,true,'center');text(s,a[1],x,328,178,42,25,K.ink,true,'center');text(s,a[2],x+1,383,178,48,16,K.muted,false,'center');if(i<5)line(s,x+98,272,x+180,272,K.teal,3);});
 rect(s,88,516,1100,86,K.navy,'none',true);text(s,'시스템 변경은 미리보기와 승인을 거친 뒤 실행하고, 같은 지표를 다시 봅니다.',114,529,1044,58,23,K.white,true,'center');
 note(s,'조치 흐름의 순서는 기능 설명이 아니라 제품의 핵심 사용자 경험을 보여 줌.');
}
// Architecture: sources converge; processing pipeline.
{
 const s=base('세 입력이 같은 분석 파이프라인으로 모인다','시스템 구조',K.violet);
 text(s,'입력',72,190,120,28,17,K.muted,true);
 node(s,78,238,238,76,'실시간 캡처','네트워크 인터페이스',K.teal);
 node(s,78,337,238,76,'pcap 파일','저장된 패킷',K.blue);
 node(s,78,436,238,76,'합성 데이터','테스트 · 실험실',K.violet);
 [276,375,474].forEach(y=>line(s,318,y,407,375,K.line,2));
 node(s,410,310,190,132,'파싱','계층별 필드 추출',K.blue);
 line(s,603,375,671,375,K.teal,5);
 node(s,678,238,194,76,'통계','속도 · 프로토콜',K.violet);
 node(s,678,337,194,76,'탐지','규칙 · 기준선',K.amber);
 node(s,678,436,194,76,'저장','SQLite',K.green);
 line(s,875,375,943,375,K.teal,5);
 node(s,950,310,238,132,'설명과 화면','FastAPI → 웹 UI',K.teal);
 text(s,'큐가 가득 차면 누락 수를 집계해 화면에 표시',420,546,485,32,17,K.amber,true,'center');
 note(s,'출처: README.md 시스템 구성 및 캡처 파이프라인.');
}
// Capture layers: intuitive stacked view.
{
 const s=base('Scapy와 Npcap은 서로 다른 일을 맡는다','Windows 실시간 캡처',K.blue);
 // Layer stack left
 const layers=[['NetCare','화면에서 캡처 시작 요청',K.navy],['Scapy','Python에서 캡처·패킷 해석 호출',K.blue],['Npcap','Windows에서 패킷 접근을 제공하는 드라이버',K.teal],['Ethernet','실제 네트워크 어댑터',K.amber]];
 layers.forEach((a,i)=>{const y=194+i*91;rect(s,99,y,620,68,K.white,K.line,true);rect(s,99,y,12,68,a[2]);text(s,a[0],130,y+8,185,50,23,a[2],true);text(s,a[1],330,y+8,355,50,18,K.body);if(i<3)text(s,'↓',370,y+65,40,24,18,K.teal,true,'center');});
 rect(s,795,226,360,280,K.navy,'none',true);
 text(s,'확인한 동작',831,260,285,40,22,K.white,true,'center');
 text(s,'Npcap Ethernet',825,325,300,44,28,'#69E0D4',true,'center');
 line(s,853,386,1098,386,'#48617B',2);
 text(s,'캡처 시작 · 패킷 수신 · 정지',822,415,310,60,18,K.white,false,'center');
 text(s,'관리자 권한으로 실행한 Windows 환경',795,540,360,34,16,K.muted,false,'center');
 note(s,'Scapy는 애플리케이션 계층 라이브러리, Npcap은 Windows 패킷 캡처 드라이버. 실제 Windows 검증 확인.');
}
// Handshake diagram
{
 const s=base('SYN Flood는 연결 완료 여부까지 본다','탐지 원리',K.red);
 text(s,'클라이언트',138,197,250,36,21,K.blue,true,'center');text(s,'서버',882,197,250,36,21,K.violet,true,'center');
 line(s,263,245,263,532,K.line,3);line(s,1007,245,1007,532,K.line,3);
 line(s,278,275,992,275,K.blue,4);text(s,'SYN',577,239,110,30,18,K.blue,true,'center');text(s,'▶',969,257,26,32,17,K.blue,true,'center');
 line(s,992,345,278,345,K.violet,4);text(s,'SYN-ACK',561,310,140,30,18,K.violet,true,'center');text(s,'◀',277,327,26,32,17,K.violet,true,'center');
 line(s,278,415,992,415,K.green,4);text(s,'ACK',580,382,100,30,18,K.green,true,'center');text(s,'▶',969,397,26,32,17,K.green,true,'center');
 rect(s,100,548,490,74,K.greenP,'none',true);text(s,'3단계 완료 → 연결 성립',120,556,450,52,20,K.green,true,'center');
 rect(s,690,548,490,74,K.amberP,'none',true);text(s,'마지막 ACK가 없으면 미완료로 집계',710,556,450,52,20,K.amber,true,'center');
 text(s,'SYN-ACK 응답률만으로는 연결이 정상 완료됐는지 알 수 없습니다.',170,474,940,42,20,K.body,false,'center');
 note(s,'탐지는 연결을 시작한 쪽의 마지막 ACK까지 추적해 핸드셰이크 완료율을 계산함. 패킷 관측만으로 공격자를 확정할 수는 없음.');
}
// False positive example as small multiples.
{
 const s=base('정상 다운로드에서 발견한 오탐을 낮췄다','실측으로 개선',K.amber);
 text(s,'89 MB',88,205,300,70,49,K.blue,true);text(s,'15초 동안 다운로드',91,277,350,32,19,K.body);
 // 15 second visual bars
 text(s,'트래픽 흐름 (개념도)',90,349,300,30,16,K.muted,true);
 const heights=[20,24,26,32,31,35,42,39,47,50,56,57,62,64,67];
 heights.forEach((h,i)=>rect(s,96+i*25,420-h,14,h,K.blue,'none',true));
 line(s,86,421,490,421,K.line,1);text(s,'0 s',88,432,60,24,13,K.muted);text(s,'15 s',447,432,60,24,13,K.muted,false,'right');
 line(s,545,220,545,522,K.line,2);
 text(s,'이전 판단',594,217,236,32,17,K.red,true);text(s,'과다 패킷 = 위험',594,266,270,52,24,K.red,true);
 text(s,'패킷 맥락을 반영',594,343,300,31,17,K.teal,true);text(s,'역방향 ACK 비율 0.19',594,385,310,35,20,K.ink,true);
 text(s,'→ 양방향 다운로드로 판단',594,423,410,35,19,K.body);
 rect(s,952,235,202,245,K.navy,'none',true);text(s,'사용량 급증',971,256,165,32,18,K.white,true,'center');text(s,'z = 7.51',969,305,170,58,31,'#7FE3D8',true,'center');text(s,'기준선과 별도 비교',972,370,164,46,16,K.white,false,'center');
 text(s,'결과: 정상 다운로드는 “위험”이 아니라 주의·정보로 표현',175,548,930,40,21,K.green,true,'center');
 note(s,'macOS 실제 다운로드 기록. EWMA 기준선 66초 학습 후 약 89MB를 15초 동안 내려받음. 실측에서 발견해 탐지 규칙을 개선한 사례.');
}
// Diagnosis UI with focused screenshot + callouts.
{
 const s=base('경고를 근거와 함께 설명한다','문제 해결 화면',K.violet);
 await pic(s,'docs/screenshots/e2e_issue_v2.png',70,174,735,438,'테스트 데이터 기반 NetCare 문제 해결 화면');
 const call=[['관측값','측정된 값과 기준'],['맥락','왜 경고인지'],['다음 행동','관련 조치와 동의 상태']];
 call.forEach((a,i)=>{const y=225+i*116;dot(s,866,y+20,13,[K.blue,K.violet,K.amber][i]);text(s,String(i+1),854,y+9,24,22,12,K.white,true,'center');text(s,a[0],902,y,260,34,22,K.ink,true);text(s,a[1],902,y+38,280,46,17,K.muted);if(i<2)line(s,866,y+37,866,y+96,K.line,2);});
 text(s,'화면은 합성 테스트 데이터 예시',820,581,380,25,14,K.muted,false,'right');
 note(s,'화면 이미지 출처: docs/screenshots/e2e_issue_v2.png. 화면 내용은 테스트·합성 데이터.');
}
// Safety gate illustrated as user controlled path.
{
 const s=base('조치 전에 영향과 부작용을 확인한다','안전한 조치',K.amber);
 // left finding, center gate, right action/effect
 rect(s,68,245,246,184,K.white,K.line,true);text(s,'탐지 결과',90,264,200,32,18,K.violet,true,'center');text(s,'차단 제안',90,320,200,47,27,K.ink,true,'center');text(s,'대상 · 영향 · 이유',90,374,200,29,16,K.muted,false,'center');
 line(s,321,337,452,337,K.blue,5);
 rect(s,464,205,337,264,K.amberP,'none',true);text(s,'사용자 승인',486,231,293,42,24,K.amber,true,'center');text(s,'실행 전 확인',500,288,260,33,18,K.ink,true,'center');
 rect(s,520,341,225,68,K.white,K.amber,true);text(s,'동의하고 실행',532,351,202,47,20,K.ink,true,'center');
 line(s,808,337,935,337,K.teal,5);
 rect(s,947,245,264,184,K.white,K.line,true);text(s,'조치 후',969,264,220,32,18,K.teal,true,'center');text(s,'효과 확인',969,320,220,47,27,K.ink,true,'center');text(s,'필요하면 되돌리기',969,374,220,29,16,K.muted,false,'center');
 text(s,'자동 차단 기본 꺼짐 · 보호 IP 차단 거부 · 실험실은 OS 방화벽을 변경하지 않음',91,544,1100,50,18,K.body,true,'center');
 note(s,'조치 흐름과 프로젝트 안전장치. Windows 방화벽 실적용/롤백은 미검증임.');
}
// Home UI screenshot
{
 const s=base('홈 화면에서 상태와 최근 탐지를 살핀다','제품 화면',K.blue);
 await pic(s,'docs/screenshots/e2e_home_test.png',86,169,910,448,'NetCare 홈 화면 테스트 데이터');
 rect(s,1004,210,198,365,K.navy,'none',true);
 text(s,'핵심 보기',1026,230,154,31,18,'#74DED3',true,'center');
 text(s,'상태\n최근 탐지\n사용량\n주요 장치',1038,298,130,205,22,K.white,true,'center');
 text(s,'테스트 데이터 화면',1015,598,178,25,13,K.muted,false,'center');
 note(s,'화면 이미지 출처: docs/screenshots/e2e_home_test.png. 합성 데이터.');
}
// Lab as controlled experiment, not product centerpiece.
{
 const s=base('실험실에서는 시나리오와 정답을 비교한다','검증 보조 도구',K.violet);
 text(s,'가상 시나리오',84,220,247,35,20,K.blue,true,'center');
 const scenarios=['정상','Port Scan','SYN Flood','DNS 장애','지연·손실'];
 scenarios.forEach((a,i)=>{const y=278+i*51;rect(s,91,y,230,37,i===0?K.greenP:K.pale,'none',true);text(s,a,105,y+2,202,31,16,i===0?K.green:K.ink,true,'center');});
 line(s,328,393,444,393,K.teal,5);
 rect(s,455,276,280,232,K.navy,'none',true);text(s,'정답 ↔ 탐지',476,303,238,42,25,K.white,true,'center');
 const metrics=[['Precision','정확도'],['Recall','재현율'],['F1','균형'],['FPR','오탐률']];metrics.forEach((a,i)=>{const x=475+(i%2)*126,y=375+Math.floor(i/2)*54;text(s,a[0],x,y,102,20,15,'#77DDD2',true,'center');text(s,a[1],x,y+21,102,23,14,K.white,false,'center');});
 line(s,741,393,840,393,K.teal,5);
 await pic(s,'docs/screenshots/e2e_lab_bench.png',780,212,425,290,'NetCare 시뮬레이션 실험실 벤치마크 설정 화면');
 text(s,'실제 네트워크와 분리 · 합성 결과를 실제 성능 보증으로 해석하지 않음',95,566,1090,39,18,K.amber,true,'center');
 note(s,'12개 시나리오, 합성 네트워크 기반. 현재 기록의 156회 결과는 규칙 업데이트 전 측정이므로 대표 성능 수치로 제시하지 않음.');
}
// Evidence: visual hierarchy around actual numbers.
{
 const s=base('Windows에서 실제 Ethernet 캡처를 확인했다','Windows 검증',K.green);
 // large metric left
 rect(s,74,205,500,350,K.navy,'none',true);text(s,'PACKETS PROCESSED',105,236,430,28,15,'#89A7C0',true);text(s,'90,316',104,286,430,104,64,K.white,true);text(s,'누락 0건',107,403,430,45,25,'#63DED0',true);text(s,'Npcap Ethernet · 관리자 권한',107,475,430,33,17,'#C1D3E2');
 text(s,'UI E2E',660,212,250,26,17,K.blue,true);text(s,'71 / 71',660,248,440,65,45,K.ink,true);text(s,'Windows Chrome',663,307,440,29,18,K.muted);
 line(s,660,357,1178,357,K.line,2);
 text(s,'pytest',660,380,250,26,17,K.violet,true);text(s,'55 / 55',660,416,440,65,45,K.ink,true);text(s,'API 테스트 제외',663,475,440,29,18,K.muted);
 rect(s,649,542,538,72,K.amberP,'none',true);text(s,'Windows API pytest는 TestClient 초기화에서 완료하지 못함. HTTP API는 별도로 확인.',665,550,507,52,16,K.amber,true,'center');
 note(s,'2026-11-17 Windows 확인. 90,316은 관찰 시점 누적 처리 수이며 처리율 지표가 아님. UI E2E 71/71, API 제외 pytest 55/55. Windows API pytest는 TestClient 초기화 단계에서 완료하지 못했고 실제 HTTP API를 별도로 확인.');
}
// Limits close
{
 const s=base('실제로 확인한 것과 남은 검증을 구분한다','한계와 다음 단계',K.red);
 // two open columns without cards
 text(s,'확인한 범위',92,205,445,38,21,K.green,true);line(s,92,250,538,250,K.green,3);
 [['Windows Npcap 이더넷 캡처','캡처 시작·정지·패킷 수신'],['자동 검증','UI 71/71 · API 제외 pytest 55/55']].forEach((a,i)=>{const y=284+i*112;dot(s,108,y+18,9,K.green);text(s,a[0],133,y,382,33,21,K.ink,true);text(s,a[1],133,y+40,382,37,16,K.muted);});
 text(s,'남은 검증',672,205,445,38,21,K.amber,true);line(s,672,250,1118,250,K.amber,3);
 [['Windows 방화벽','실제 적용과 롤백'],['다른 환경','Linux 실기기 · 장시간 연속 운용'],['실험실','최신 규칙으로 벤치마크 갱신']].forEach((a,i)=>{const y=278+i*86;dot(s,688,y+18,9,K.amber);text(s,a[0],713,y,180,32,19,K.ink,true);text(s,a[1],892,y,275,35,16,K.muted);});
 rect(s,95,568,1090,64,K.navy,'none',true);text(s,'핵심: 이상을 발견하는 데서 멈추지 않고, 근거와 안전한 복구까지 연결한다.',117,578,1045,44,21,K.white,true,'center');
 note(s,'미검증을 통과한 것처럼 표현하지 않는다.');
}

for(let i=0;i<p.slides.items.length;i++){const b=await p.export({slide:p.slides.items[i],format:'png',scale:1});await fs.writeFile(path.join(build,`visual-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await b.arrayBuffer()));}
const montage=await p.export({format:'png',montage:true});await fs.writeFile(path.join(build,'visual-montage.png'),new Uint8Array(await montage.arrayBuffer()));
const candidate=path.join(root,'.codex-finalizer','visual-candidate.pptx');await fs.mkdir(path.dirname(candidate),{recursive:true});await (await PresentationFile.exportPptx(p)).save(candidate);
const skill='C:/Users/l22s2/.codex/plugins/cache/openai-primary-runtime/presentations/26.1112.11217/skills/presentations';
const {finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')).href);
const result=await finalizePresentation({workspaceDir:root,candidatePath:candidate,finalPath,pythonExecutable:'C:/Program Files/WindowsApps/OpenAI.CodexPrimaryRuntime.v26-1112-737-0_26.1112.737.0_x64__3k8sg7r9htsxt/dependencies/python/python.exe',integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit'],requiredNativeTableOwnerSlides:[],fontPolicy:{basis:'design',families:[F]},verifyArtifactToolImport:true,receiptPath:path.join(root,'.codex-finalizer','visual.validation.json')});
console.log(JSON.stringify({finalPath,slideCount:p.slides.items.length,result},null,2));
