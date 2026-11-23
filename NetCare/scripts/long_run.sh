#!/usr/bin/env bash
# 장시간 실측 — NetCare 서버를 따로 띄워 실제 인터페이스를 N시간 캡처하고, 끝나면 요약을 만든다.
#
#   scripts/long_run.sh en5 6            # en5 를 6시간
#   scripts/long_run.sh en5 6 /tmp/run1  # 결과 폴더 지정
#
# 사용자의 평소 NetCare(포트 8765)와 DB 는 건드리지 않는다 (포트 8790, 별도 데이터 폴더).
# 공격 트래픽을 보내지 않는다 (캡처만). 맥이 잠들지 않도록 caffeinate 로 감싼다.
set -euo pipefail
IFACE="${1:?인터페이스 이름 (예: en5)}"
HOURS="${2:-6}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${3:-$HOME/NetCare_longrun_$(date +%Y%m%d_%H%M)}"
PY="$ROOT/.venv/bin/python"
mkdir -p "$OUT/data"
cd "$ROOT"
NETCARE_DATA_DIR="$OUT/data" nohup "$PY" run.py --port 8790 --no-browser > "$OUT/server.log" 2>&1 &
SERVER=$!
for i in $(seq 1 30); do curl -s http://127.0.0.1:8790/api/status >/dev/null && break; sleep 1; done
curl -s -X POST -H 'X-NetCare: 1' -H 'Content-Type: application/json' -d "{\"iface\":\"$IFACE\"}" http://127.0.0.1:8790/api/capture/start | head -c 200; echo
echo "시작: $(date) · $IFACE · ${HOURS}시간 · 결과 $OUT"
caffeinate -i -s "$PY" scripts/perf_monitor.py --base http://127.0.0.1:8790 --pid $SERVER --duration $((HOURS*3600)) \
  --db "$OUT/data/netcare.db" --out "$OUT/perf.csv" --diag "$OUT/diag.jsonl" --top-every 0 > "$OUT/monitor.log" 2>&1
curl -s -X POST -H 'X-NetCare: 1' http://127.0.0.1:8790/api/capture/stop > /dev/null || true
kill $SERVER 2>/dev/null || true
"$PY" scripts/bench/live_summary.py --dir "$OUT" --out "$OUT/summary.json" --md "$OUT/summary.md" > /dev/null
echo "끝: $(date)"
cat "$OUT/summary.md"
