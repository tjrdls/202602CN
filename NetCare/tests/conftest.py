import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# 테스트는 별도 데이터 폴더를 사용 (실사용 DB/설정 오염 방지)
os.environ.setdefault("NETCARE_DATA_DIR", tempfile.mkdtemp(prefix="netcare-test-"))
