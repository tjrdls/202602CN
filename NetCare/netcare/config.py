"""NetCare 설정 관리.

모든 임계값은 이 파일의 기본값에서 시작하며, 사용자가 설정 화면에서 바꾸면
data/config.json 에 저장된다. 코드 곳곳에 숫자를 흩뿌리지 않기 위해
탐지/저장/조치 관련 값은 전부 여기에 모아 둔다.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _default_data_dir() -> Path:
    # 단일 실행 파일(PyInstaller)은 임시 폴더에서 풀려 실행되므로, 기록은 사용자 폴더에 둔다
    if getattr(__import__("sys"), "frozen", False):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        return Path(base) / "NetCare"
    return BASE_DIR / "data"


DATA_DIR = Path(os.environ.get("NETCARE_DATA_DIR") or _default_data_dir())


@dataclass
class DetectionConfig:
    window_sec: int = 10                 # 슬라이딩 윈도우 길이(초)
    ip_pps_threshold: float = 300.0      # ① 한 IP의 초당 패킷 수
    syn_threshold: int = 60              # ② 윈도우 내 순수 SYN 개수
    syn_success_ratio_max: float = 0.3   # ② 연결 성공률(SYN-ACK/SYN)이 이보다 낮아야 의심
    port_share_threshold: float = 0.8    # ③ 한 포트가 차지하는 패킷 비율
    port_min_packets: int = 2000         # ③ 윈도우 내 최소 패킷 수
    traffic_z_threshold: float = 4.0     # ④ 통계 기준선 대비 z-score
    traffic_min_bps: float = 1_000_000   # ④ 통계 탐지 최소 바이트/초 (1MB/s)
    traffic_static_bps: float = 10_000_000  # ④ 워밍업 전 고정 임계값 (10MB/s)
    warmup_sec: int = 60                 # ④ 기준선 학습 시간
    repeat_conn_threshold: int = 30      # ⑤-a 같은 목적지:포트 SYN 반복
    port_scan_threshold: int = 40        # ⑤-b 서로 다른 목적지:포트 수
    peer_share_threshold: float = 0.9    # ⑤-c 한 IP의 바이트 점유율
    peer_min_bps: float = 2_000_000      # ⑤-c 최소 바이트/초
    dns_failure_threshold: int = 5       # DNS 오류+무응답 건수
    dns_failure_ratio: float = 0.5       # DNS 실패 비율
    cooldown_sec: int = 60               # 같은 징후 재알림 억제 시간
    # ── 확장 규칙 (스푸핑 · 연결 품질) ──
    spoof_min_indicators: int = 5        # IP 스푸핑 의심: 윈도우 내 위조 징후 최소 개수
    ttl_deviation: int = 8               # 같은 출발지의 평소 TTL 과의 차이 (홉 수)
    dns_spoof_min_events: int = 2        # DNS 위조 의심: 상충 응답·엉뚱한 서버 응답 등 최소 건수
    latency_ms: float = 150.0            # 지연: 왕복 시간(RTT) 중앙값 기준
    latency_min_samples: int = 5
    jitter_ms: float = 50.0              # 지터: 같은 상대에 대한 연속 RTT 차이 평균 기준
    jitter_min_samples: int = 12
    loss_ratio: float = 0.05             # 손실: (재전송+3중 중복 ACK) / 데이터 세그먼트
    loss_min_segments: int = 50
    conn_fail_attempts: int = 3          # 연결 중단: 이전에 되던 서버로 응답 없는 SYN 횟수
    bw_flat_cv: float = 0.10             # 대역폭 제한 의심: 처리량 변동계수 이하(평평함)
    bw_min_seconds: int = 8
    bw_rtt_inflation_ms: float = 100.0   # 대역폭 제한 의심: 평소보다 늘어난 RTT
    size_anomaly_bytes: int = 1000       # 비정상 패킷 크기: ICMP/DNS 페이로드가 이 이상이면 '대형'
    size_anomaly_min_count: int = 10     # 비정상 패킷 크기: 윈도우 내 대형 ICMP/DNS 패킷 최소 개수
    proto_shift_min_pps: int = 100       # 프로토콜 비율 이상: 윈도우 평균 PPS 가 이 이상일 때만 판단
    proto_shift_delta: float = 0.5       # 프로토콜 비율 이상: 평소 비율 대비 늘어난 절대 비율(0~1)
    nxdomain_threshold: int = 20         # DNS 응답 이상: 윈도우 내 NXDOMAIN 응답 수
    nxdomain_min_names: int = 10         # DNS 응답 이상: 서로 다른 도메인 수
    whitelist: list[str] = field(default_factory=list)  # 탐지/차단 제외 IP 또는 CIDR


@dataclass
class ProbeConfig:
    enabled: bool = True
    interval_sec: int = 30
    external_target: str = "1.1.1.1"
    dns_test_domains: list[str] = field(default_factory=lambda: ["www.google.com", "www.naver.com"])
    gateway_loss_warn: float = 50.0      # % — 이 이상이면 이상 징후
    latency_warn_ms: float = 200.0


@dataclass
class AppConfig:
    interface: str = ""
    bpf_filter: str = ""
    max_db_packets: int = 300_000        # 패킷 테이블 보존 한도
    store_raw: bool = True               # 상세 분석용 원본 바이트 저장
    raw_snaplen: int = 2048              # 저장할 원본 최대 바이트
    ring_size: int = 5000                # 화면용 최근 패킷 링버퍼
    queue_size: int = 50_000             # 캡처 → 처리 큐 크기
    auto_block_enabled: bool = False     # 자동 차단 (기본 비활성)
    auto_block_ttl_min: int = 30         # 자동 차단 유지 시간
    expert_mode_default: bool = False
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    probe: ProbeConfig = field(default_factory=ProbeConfig)


def _merge(dc_obj, data: dict):
    """dict 의 값을 dataclass 에 타입을 맞춰 덮어쓴다. 모르는 키는 무시."""
    for f in fields(dc_obj):
        if f.name not in data:
            continue
        cur = getattr(dc_obj, f.name)
        val = data[f.name]
        if hasattr(cur, "__dataclass_fields__"):
            if isinstance(val, dict):
                _merge(cur, val)
            continue
        try:
            if isinstance(cur, bool):
                val = bool(val)
            elif isinstance(cur, int):
                val = int(val)
            elif isinstance(cur, float):
                val = float(val)
            elif isinstance(cur, list):
                val = [str(v).strip() for v in val if str(v).strip()]
            elif isinstance(cur, str):
                val = str(val)
        except (TypeError, ValueError):
            raise ValueError(f"설정 값 '{f.name}' 형식이 올바르지 않아요: {val!r}")
        setattr(dc_obj, f.name, val)


def validate(cfg: AppConfig) -> None:
    d = cfg.detection
    positives = {
        "window_sec": d.window_sec, "ip_pps_threshold": d.ip_pps_threshold,
        "syn_threshold": d.syn_threshold, "port_min_packets": d.port_min_packets,
        "traffic_z_threshold": d.traffic_z_threshold, "repeat_conn_threshold": d.repeat_conn_threshold,
        "port_scan_threshold": d.port_scan_threshold, "dns_failure_threshold": d.dns_failure_threshold,
        "max_db_packets": cfg.max_db_packets, "ring_size": cfg.ring_size, "queue_size": cfg.queue_size,
        "interval_sec": cfg.probe.interval_sec,
    }
    for k, v in positives.items():
        if v <= 0:
            raise ValueError(f"'{k}' 값은 0보다 커야 해요.")
    for k in ("syn_success_ratio_max", "port_share_threshold", "peer_share_threshold", "dns_failure_ratio", "loss_ratio", "bw_flat_cv", "proto_shift_delta"):
        v = getattr(d, k)
        if not 0 < v <= 1:
            raise ValueError(f"'{k}' 값은 0과 1 사이여야 해요.")
    if d.window_sec > 120:
        raise ValueError("윈도우는 120초 이하로 설정해 주세요.")
    import ipaddress
    for w in d.whitelist:
        try:
            ipaddress.ip_network(w, strict=False)
        except ValueError:
            raise ValueError(f"화이트리스트 항목 '{w}' 은(는) IP 또는 CIDR 형식이 아니에요.")


class ConfigStore:
    """스레드 안전한 설정 저장소."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else DATA_DIR / "config.json"
        self._lock = threading.RLock()
        self.cfg = AppConfig()
        self.load()

    def load(self) -> None:
        with self._lock:
            if self.path.exists():
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    _merge(self.cfg, data)
                    validate(self.cfg)
                except (OSError, ValueError, json.JSONDecodeError):
                    # 손상된 설정은 기본값으로 되돌리고 원본을 보존
                    self.path.rename(self.path.with_suffix(".broken.json"))
                    self.cfg = AppConfig()

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(asdict(self.cfg), ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def update(self, data: dict) -> AppConfig:
        """부분 업데이트. 검증에 실패하면 이전 값을 유지한다."""
        with self._lock:
            backup = json.loads(json.dumps(asdict(self.cfg)))
            try:
                _merge(self.cfg, data)
                validate(self.cfg)
            except ValueError:
                self.cfg = AppConfig()
                _merge(self.cfg, backup)
                raise
            self.save()
            return self.cfg

    def as_dict(self) -> dict:
        with self._lock:
            return asdict(self.cfg)
