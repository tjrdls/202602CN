# 공개 데이터셋 벤치마크: CSE-CIC-IDS2018 — NetCare vs CrowdSec

같은 패킷을 두 도구에 넣어 비교했습니다. NetCare는 pcap을 그대로 분석하고, CrowdSec은 같은 패킷에서 만든 웹 서버(Apache) 접근 로그와 vsftpd 로그를 읽습니다(실제 CrowdSec을 GitHub Actions에서 time-machine 모드로 실행).

- 데이터: [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) (CIC·CSE, AWS 공개 버킷), 공격받은 서버의 호스트 캡처만 사용
- 정답: 같은 데이터셋의 CICFlowMeter 라벨 CSV. 라벨 시각은 오전/오후 표시가 없는 12시간제라 01~06시를 오후로 고치고, pcap의 새 연결 분포와 맞춰 시간대를 정한 뒤 공격 구간·공격자 주소를 정했습니다.
- NetCare 탐지 중 `ext_`로 시작하는 시나리오는 CrowdSec에 없는 NetCare 확장 조건(URL 디코딩 후 비교, SQL 문법, 로그인 반복)입니다.
- SSH는 암호화되어 sshd 인증 실패 로그를 패킷으로 만들 수 없으므로 CrowdSec은 '측정 불가'입니다(실제 서버에서는 sshd 로그로 탐지 가능).

| 사례 | 공격(라벨) | 공격 구간(UTC) | 공격자 | NetCare | 소요 | NetCare 시나리오 | CrowdSec | 소요 | CrowdSec 시나리오 |
|---|---|---|---|---|---|---|---|---|---|
| Wednesday-14-02-2018 | FTP-BruteForce (193,360흐름) | 14:33–16:11 | 18.221.219.4 | ❌ | -초 | - | ❌ | -초 | - |
| Wednesday-14-02-2018 | SSH-Bruteforce (187,589흐름) | 18:01–19:33 | 13.58.98.64 | ✅ | 51.0초 | ssh_bf | — | -초 | sshd 로그 필요 (패킷으로 만들 수 없음) → 측정 불가 |
| Thursday-22-02-2018 | Brute Force -Web (249흐름) | 14:13–15:24 | 18.218.115.60 | ✅ | 342.0초 | ext_http_login_bf | ❌ | -초 | - |
| Thursday-22-02-2018 | Brute Force -XSS (79흐름) | 17:51–18:29 | 18.218.115.60 | ✅ | 47.0초 | ext_xss_decoded | ❌ | -초 | - |
| Thursday-22-02-2018 | SQL Injection (34흐름) | 15:09–20:28 | 18.218.115.60 | ✅ | 18570.0초 | ext_sqli | ❌ | -초 | - |
| Friday-23-02-2018 | Brute Force -Web (362흐름) | 14:04–15:03 | 18.218.115.60 | ✅ | 44.0초 | ext_http_login_bf | ❌ | -초 | - |
| Friday-23-02-2018 | Brute Force -XSS (151흐름) | 17:01–18:11 | 18.218.115.60 | ✅ | 12.0초 | ext_xss_decoded | ❌ | -초 | - |
| Friday-23-02-2018 | SQL Injection (53흐름) | 14:22–19:18 | 18.218.115.60 | ✅ | 17103.0초 | ext_sqli | ❌ | -초 | - |

## 라벨 밖 탐지 (공격 구간·공격자와 맞지 않는 보안 알림)

라벨은 실험자가 낸 공격만 표시합니다. 인터넷에 열린 실험 서버라 실제 외부 스캐너·무차별 대입이 섞여 있으므로, 아래가 모두 오탐인 것은 아닙니다.

- **Wednesday-14-02-2018** (캡처 8.94시간, 패킷 4,718,328개): NetCare 5건 (http_admin_probing 120.76.195.219, http_probing 120.76.195.219, ip_packet_flood 172.31.69.25, ip_packet_flood 52.219.80.154) · CrowdSec 2건 (crowdsecurity/http-admin-interface-probing 120.76.195.219, crowdsecurity/http-probing 120.76.195.219) · NetCare 비보안 알림(품질·사용량): {'port_concentration': 2}
- **Thursday-22-02-2018** (캡처 9.08시간, 패킷 47,715개): NetCare 1건 (ssh_bf 199.195.249.132) · CrowdSec 0건 · NetCare 비보안 알림(품질·사용량): {'tcp_loss': 1}
- **Friday-23-02-2018** (캡처 9.2시간, 패킷 55,102개): NetCare 0건 · CrowdSec 0건

## 진단: FTP 서버 응답

- **Wednesday-14-02-2018**: 서버→클라이언트 TCP 플래그 {'RA': 193392}, 클라이언트→서버 {'S': 193392}, 서버 응답 코드 None
- **Friday-23-02-2018**: 서버→클라이언트 TCP 플래그 {'RA': 4}, 클라이언트→서버 {'S': 3, 'SEC': 1}, 서버 응답 코드 None

생성: 2026-11-22 14:04 UTC · 스크립트: `scripts/bench/cse_cic_ids2018.py`, `scripts/bench/report.py` · 워크플로: `.github/workflows/netcare-bench.yml`
