# NetCare

초보자 친화형 실시간 네트워크 패킷 분석 및 자동 문제 해결 시스템입니다. 패킷을 수집·분석해 이상 징후를 설명하고, 사용자 승인 후 조치와 검증·되돌리기를 지원합니다. 실제 네트워크에 영향을 주지 않는 가상 공격 실험실도 포함합니다.

## 실행

Python 3.10 이상이 필요합니다.

```bash
cd NetCare
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
```

서버는 기본적으로 `http://127.0.0.1:8765`에서 실행됩니다. 실시간 캡처는 운영체제별 권한과 Windows의 경우 Npcap 설치가 필요합니다. 캡처 권한이 없어도 pcap 파일 분석, 테스트 데이터, 가상 실험실을 사용할 수 있습니다.

## 문서

- [설치·사용법·시스템 구조](NetCare/README.md)
- [테스트 및 실험 결과](NetCare/docs/02_테스트_결과.md)
- [고도화 및 남은 과제](NetCare/docs/06_고도화_계획.md)

## 저장소 구성

구현과 관련 자료는 [`NetCare/`](NetCare/)에 있습니다. 실행 중 생성되는 DB·설정·pcap 데이터는 로컬 `data/`에 저장됩니다.
