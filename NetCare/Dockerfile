# syntax=docker/dockerfile:1
# NetCare 실행 이미지 — 파이썬·라이브러리·캡처 도구·한글 글꼴을 모두 포함한다.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="NetCare" \
      org.opencontainers.image.description="초보자 친화형 실시간 네트워크 패킷 분석 및 자동 문제 해결 시스템" \
      org.opencontainers.image.source="https://github.com/tjrdls/202602CN"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETCARE_CONTAINER=1 \
    NETCARE_DATA_DIR=/data \
    NETCARE_HOST=0.0.0.0 \
    NETCARE_PORT=8765

# libpcap·tcpdump: 캡처와 BPF 필터 컴파일 / iputils-ping: 연결 점검 / fonts-nanum: 한글 PDF 리포트
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 tcpdump iputils-ping fonts-nanum \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# 실행에 필요한 패키지만 설치 (pytest·httpx 같은 테스트 도구는 제외)
RUN grep -vE '^\s*(pytest|httpx)' requirements.txt > /tmp/req.txt \
 && pip install -r /tmp/req.txt \
 && rm /tmp/req.txt

COPY run.py .
COPY netcare ./netcare

VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"NETCARE_PORT\",\"8765\")}/api/status', timeout=4)" || exit 1

CMD ["python", "run.py", "--no-browser"]
