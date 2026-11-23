# Windows 실제 캡처 검증 가이드

Windows 실제 캡처(Npcap)는 아직 **미검증**입니다.
- GitHub Actions에는 Npcap을 설치할 수 없습니다. Chocolatey에 패키지가 없고, 무료판은 무인 설치를 지원하지 않습니다.
- 그래서 Windows 커널 통계(`pcap_stats`)와 새 캡처 경로(원시 프레임 큐·빠른 해석 경로·인터페이스 분리 감지)는 가짜 소켓 단위 테스트만 통과한 상태입니다.

아래 순서대로 Windows PC에서 한 번 실행하면 macOS·Linux와 같은 6개 항목을 실제로 확인할 수 있습니다. 약 5분 걸립니다.

## 1. 준비 (한 번만)
1. **Python 3.10 이상**을 설치합니다([python.org](https://www.python.org/downloads/)). 설치 화면에서 "Add python.exe to PATH"를 체크합니다.
2. **Npcap**을 설치합니다([npcap.com](https://npcap.com/#download)).
   - 설치 옵션에서 **"Support loopback traffic ('Npcap Loopback Adapter' will be created)"** 을 반드시 체크합니다. 6번 항목(루프백 고속 유입) 시험에 필요합니다.
   - "WinPcap API-compatible Mode"는 켜도 되고 꺼도 됩니다.
3. 저장소를 받습니다.
   ```bat
   git clone https://github.com/tjrdls/202602CN.git
   cd 202602CN\NetCare
   py -m venv .venv
   .venv\Scripts\pip install -r requirements.txt
   ```

## 2. 점검 실행
**시작 메뉴 → "명령 프롬프트" 우클릭 → 관리자 권한으로 실행** 후:

```bat
cd 202602CN\NetCare
.venv\Scripts\python scripts\os_capture_check.py --seconds 30 --out windows_check.json
```

- 인터페이스는 기본 경로(인터넷이 나가는 어댑터)를 자동으로 고릅니다. 직접 지정하려면 `--iface "이더넷"` 또는 `--iface "Wi-Fi"`처럼 화면에 보이는 이름을 씁니다.
- 시험 중 보내는 트래픽은 두 가지뿐입니다.
  - example.com DNS 조회와 HTTPS 접속 몇 번
  - 루프백(127.0.0.1) 닫힌 포트로의 UDP
- 마지막 줄에 `요약: 모두 통과` 또는 실패 항목이 나옵니다. 만들어진 **`windows_check.json`** 파일을 공유해 주세요.

## 3. 확인하는 것
| # | 항목 | 통과 기준 |
|---|---|---|
| 1 | 환경 | Scapy가 libpcap(Npcap) 소켓을 씀 (`L2listen = L2pcapListenSocket`) |
| 2 | 인터페이스 | 화면 이름("이더넷") → Npcap 장치(`\Device\NPF_{...}`) 변환 성공 |
| 3 | 실제 캡처·커널 통계 | 원시 프레임 수신 + `pcap_stats`(수신·누락·드라이버 누락) 읽기 |
| 4 | 해석 대조 | 잡은 실제 패킷에서 빠른 경로 = Scapy 경로 (불일치 0) |
| 5 | 엔진 실캡처 | NetCare 엔진이 응용·커널 단계 통계를 10초마다 기록 |
| 6 | 루프백 고속 유입 | 초당 2,000 / 10,000개 유입에서 커널 통계·처리 확인 (Npcap 루프백 어댑터 필요) |

## 4. 화면으로도 확인 (선택)
`.venv\Scripts\python run.py`를 실행합니다. 같은 확인을 `NetCare.exe`(Actions → NetCare CI → Artifacts)로 해도 됩니다.
1. **캡처 시작 → 실시간 캡처**를 누릅니다.
2. 홈 화면 아래 **캡처 상태 · 패킷 누락** 카드에 '커널 단계 · libpcap' 값이 나오는지 봅니다.
3. 캡처 중에 랜선을 뽑거나 Wi-Fi를 끕니다. 20초 안에 "인터페이스 연결이 끊겨 캡처를 멈췄어요"가 나오는지 봅니다.
   - Windows 인터페이스 이름이 OS 목록과 다르면 이 감지는 동작하지 않도록 설계돼 있습니다. 이때도 오판으로 캡처를 끊지 않아야 합니다.
