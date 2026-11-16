"""탐지 규칙 카탈로그: 규칙마다 조건·임계값(현재 설정값)·근거·위험 수준·오탐 가능성·적용 환경·한계를 한곳에 정리한다.

설명문 안에 흩어져 있던 지식을 구조화해 화면(전문가 모드·문제 해결·전역 검색)과 문서가 같은 내용을 보도록 한다.
임계값은 DetectionConfig 의 필드 이름으로 참조하고, rule_catalog() 가 현재 값으로 채운다.
"""
from __future__ import annotations

from netcare.config import DetectionConfig

# category: attack(공격 패턴) | usage(사용량·트래픽) | quality(품질·장애) | dns | spoof(위조 의심)
RULES: list[dict] = [
    dict(type="ip_packet_flood", label="특정 장치의 과도한 패킷", category="usage", basis="packet",
         condition="한 IP가 보낸 패킷이 초당 {ip_pps_threshold}개 이상 (윈도우 {window_sec}초 평균)",
         thresholds=["ip_pps_threshold", "window_sec"], severity="정보~위험 (기준 대비 배수와 양방향 여부로 결정)", certainty="measured",
         evidence="출발지별 패킷 수, 역방향 ACK 비율로 양방향 통신 판정",
         false_positives=["대용량 다운로드·백업(양방향이면 등급을 낮춤)", "로컬 스트리밍·화면 공유"],
         environments=["가정·사무실 LAN", "서버"], limits=["캡처 지점을 지나지 않는 트래픽은 못 봄", "분산 출발지 폭주는 ②·③ 규칙이 담당"]),
    dict(type="syn_surge", label="새로운 연결 요청 급증 (SYN Flood 패턴)", category="attack", basis="packet",
         condition="{window_sec}초 동안 순수 SYN {syn_threshold}개 이상이면서 3-way 핸드셰이크 완료율이 {syn_success_ratio_max:.0%} 미만",
         thresholds=["syn_threshold", "syn_success_ratio_max", "window_sec"], severity="주의~위험 (완료율 0%·출발지 분산이면 위험)", certainty="measured",
         evidence="SYN·SYN-ACK·마지막 ACK 추적으로 계산한 완료율, 출발지 수",
         false_positives=["연결을 많이 여는 브라우저(완료율이 높아 제외됨)", "서버가 꺼져 있을 때의 재시도(완료율 낮음)"],
         environments=["서버·NAS를 운영하는 LAN", "내 컴퓨터가 서비스 중일 때"], limits=["SYN 쿠키를 쓰는 서버는 SYN-ACK는 보내므로 완료율로만 판단", "SYN-ACK 응답률이 아니라 완료율을 쓰는 이유: 피해 서버도 SYN-ACK는 보냄"]),
    dict(type="port_concentration", label="특정 포트 집중", category="usage", basis="packet",
         condition="{window_sec}초 동안 패킷 {port_min_packets}개 이상이면서 한 포트가 {port_share_threshold:.0%} 이상 차지",
         thresholds=["port_share_threshold", "port_min_packets", "window_sec"], severity="정보 (HTTPS 같은 일반 서비스 포트) ~ 주의", certainty="measured",
         evidence="서비스 포트별 패킷 점유율", false_positives=["HTTPS 443 위주의 정상 웹 사용(정보 등급으로 낮춤)", "대용량 단일 전송"],
         environments=["모든 환경"], limits=["포트만으로는 응용 프로그램을 확정할 수 없음"]),
    dict(type="traffic_surge", label="네트워크 사용량 급증", category="usage", basis="statistical",
         condition="초당 바이트가 EWMA 기준선 대비 z-score {traffic_z_threshold:g} 이상이고 {traffic_min_bps:,.0f}B/s 이상 (학습 {warmup_sec}초 전에는 {traffic_static_bps:,.0f}B/s 고정)",
         thresholds=["traffic_z_threshold", "traffic_min_bps", "traffic_static_bps", "warmup_sec"], severity="정보~주의", certainty="measured",
         evidence="EWMA 평균·분산(α=0.05), 이상 구간은 학습에서 제외", false_positives=["다운로드 시작 순간(정상 사용량 변화)"],
         environments=["사용 패턴이 일정한 환경에서 의미가 큼"], limits=["기준선이 하나(장치·시간대별 기준선 없음)", "학습 전에는 고정 임계값"]),
    dict(type="repeated_connection", label="반복되는 연결 시도", category="attack", basis="packet",
         condition="{window_sec}초 동안 같은 목적지·포트로 SYN {repeat_conn_threshold}회 이상이면서 완료율 50% 미만",
         thresholds=["repeat_conn_threshold", "window_sec"], severity="주의~위험", certainty="measured",
         evidence="(출발지, 목적지, 포트)별 SYN·완료 수", false_positives=["꺼진 서버로의 자동 재시도", "정상 API 폴링(완료되면 제외)"],
         environments=["RDP·SSH 등 원격 접속 포트를 연 환경"], limits=["연결이 성공하는 로그인 무차별 대입(SSH 등)은 잡지 못함"]),
    dict(type="port_scan", label="여러 포트 탐색 패턴 (포트 스캔)", category="attack", basis="packet",
         condition="{window_sec}초 동안 한 출발지가 서로 다른 (목적지, 포트) {port_scan_threshold}개 이상에 SYN 또는 UDP 전송",
         thresholds=["port_scan_threshold", "window_sec"], severity="주의~위험 (외부 출발지면 위험)", certainty="measured",
         evidence="출발지별 서로 다른 목적지·포트 집합(서비스 포트에서 오는 UDP 응답은 제외)", false_positives=["네트워크 검색 도구·프린터 탐색", "P2P 프로그램"],
         environments=["모든 환경"], limits=["느린 스캔(윈도우보다 긴 간격)은 놓침"]),
    dict(type="heavy_peer", label="특정 장치와의 과도한 통신", category="usage", basis="packet",
         condition="한 IP의 바이트가 전체의 {peer_share_threshold:.0%} 이상이고 {peer_min_bps:,.0f}B/s 이상",
         thresholds=["peer_share_threshold", "peer_min_bps"], severity="정보", certainty="measured",
         evidence="출발지별 바이트 점유율", false_positives=["대용량 다운로드·스트리밍"], environments=["모든 환경"], limits=["정상 대용량 전송과 구분 불가 → 정보 등급"]),
    dict(type="dns_failure", label="도메인 주소 조회(DNS) 실패", category="dns", basis="packet",
         condition="{window_sec}초 동안 DNS 오류+무응답 {dns_failure_threshold}건 이상이면서 실패율 {dns_failure_ratio:.0%} 이상",
         thresholds=["dns_failure_threshold", "dns_failure_ratio", "window_sec"], severity="주의~위험", certainty="measured",
         evidence="질의 ID 매칭, 3초 무응답, rcode≠0. 같은 도메인의 A가 성공하면 AAAA 무응답은 제외. mDNS·LLMNR 제외",
         false_positives=["IPv6(AAAA)만 실패하는 환경(제외 처리)", "존재하지 않는 도메인 오타"], environments=["모든 환경"], limits=["암호화 DNS(DoH/DoT)는 내용을 볼 수 없음"]),
    dict(type="gateway_unreachable", label="공유기(게이트웨이) 연결 끊김", category="quality", basis="probe",
         condition="공유기 ping 손실률이 기준 이상 (연결 점검 설정)", thresholds=[], severity="위험", certainty="measured",
         evidence="주기적 ping 실측", false_positives=["ICMP 응답을 막은 공유기"], environments=["게이트웨이가 ping에 응답하는 환경"], limits=["점검 간격 사이의 짧은 끊김은 못 봄"]),
    dict(type="packet_loss", label="데이터 손실 발생 (ping)", category="quality", basis="probe",
         condition="공유기·인터넷 ping 손실률이 기준 이상", thresholds=[], severity="주의~위험", certainty="measured",
         evidence="주기적 ping 실측", false_positives=["ICMP를 낮은 우선순위로 처리하는 구간"], environments=["모든 환경"], limits=["TCP 손실과는 별개(tcp_loss 규칙 참고)"]),
    dict(type="high_latency", label="네트워크 지연 (ping)", category="quality", basis="probe",
         condition="ping 평균 지연이 기준 이상", thresholds=[], severity="주의", certainty="measured",
         evidence="주기적 ping 실측", false_positives=["원래 먼 지역의 대상"], environments=["모든 환경"], limits=["점검 대상 1곳 기준"]),
    dict(type="arp_spoof", label="ARP 스푸핑 의심", category="spoof", basis="packet",
         condition="{window_sec}초 동안 같은 IP(내 서브넷 안)에 서로 다른 MAC이 2회 이상 번갈아 나타남, 요청 없는 ARP 응답 반복",
         thresholds=["window_sec"], severity="주의 (게이트웨이 사칭이면 위험)", certainty="likely",
         evidence="IP→MAC 바인딩 변화, 요청 없는 응답 수, 의심 MAC으로 간 내 프레임 수", false_positives=["DHCP 재할당·장비 교체", "이중화된 게이트웨이(VRRP)"],
         environments=["이더넷·Wi-Fi LAN"], limits=["서브넷 밖 주소는 판단하지 않음(실측 오탐 사례)", "확정이 아니라 의심"]),
    dict(type="ip_spoof_suspect", label="IP 스푸핑(출발지 위조) 의심", category="spoof", basis="packet",
         condition="{window_sec}초 동안 위조 징후(내 IP를 외부 MAC이 사용, 예약·보곤 주소, LAN IP-MAC 불일치, TTL이 평소와 {ttl_deviation}홉 이상 차이, 요청 없는 SYN-ACK) {spoof_min_indicators}개 이상",
         thresholds=["spoof_min_indicators", "ttl_deviation", "window_sec"], severity="최대 주의 (확정 불가)", certainty="suspected",
         evidence="징후 종류별 개수와 예시", false_positives=["여러 MAC을 쓰는 IP(가상화·로드밸런서)는 제외", "경로 변경에 따른 TTL 변화"],
         environments=["모든 환경"], limits=["TTL까지 맞춘 위조는 구분 불가", "패킷만으로 위조를 확정할 수 없음"]),
    dict(type="dns_spoof_suspect", label="DNS 응답 위조 의심", category="spoof", basis="packet",
         condition="{window_sec}초 동안 같은 질의에 상충하는 응답, 설정한 DNS 서버가 아닌 곳의 응답, DNS 서버 MAC 변경이 {dns_spoof_min_events}건 이상",
         thresholds=["dns_spoof_min_events", "window_sec"], severity="최대 주의 (확정 불가)", certainty="suspected",
         evidence="질의 ID별 응답 비교, 서버 주소·MAC", false_positives=["CDN의 다른 응답(동일 ID 안에서는 드묾)", "DNS 서버 변경"],
         environments=["평문 DNS(UDP 53) 사용 환경"], limits=["처음부터 위조 응답 하나만 오면 구분 불가", "DoH/DoT는 볼 수 없음"]),
    dict(type="latency_rise", label="네트워크 지연 증가 (패킷 기반 RTT)", category="quality", basis="packet",
         condition="SYN→SYN-ACK·DNS 질의→응답 RTT 중앙값이 {latency_ms:g}ms 이상 (표본 {latency_min_samples}개 이상)",
         thresholds=["latency_ms", "latency_min_samples", "window_sec"], severity="주의", certainty="measured",
         evidence="Karn 규칙(재전송 SYN 제외) RTT 표본, 평소 기준선", false_positives=["원래 먼 서버 위주의 통신"], environments=["모든 환경"], limits=["표본이 적은 조용한 네트워크에서는 판단 안 함"]),
    dict(type="jitter_high", label="지연 시간 불규칙(지터)", category="quality", basis="packet",
         condition="같은 상대에 대한 연속 RTT 차이의 중앙값이 {jitter_ms:g}ms 이상 (표본 {jitter_min_samples}개 이상)",
         thresholds=["jitter_ms", "jitter_min_samples", "window_sec"], severity="주의", certainty="measured",
         evidence="상대별 연속 RTT 차이", false_positives=["지연이 계단식으로 바뀌는 순간(중앙값으로 완화)"], environments=["모든 환경"], limits=["중앙값 방식이라 탐지가 몇 초 늦음(Recall 트레이드오프)"]),
    dict(type="tcp_loss", label="데이터 손실(재전송 증가)", category="quality", basis="packet",
         condition="(재전송 + 3중 중복 ACK) / 데이터 세그먼트가 {loss_ratio:.0%} 이상 (세그먼트 {loss_min_segments}개 이상), ping 무응답 보조",
         thresholds=["loss_ratio", "loss_min_segments", "window_sec"], severity="주의~위험", certainty="measured",
         evidence="흐름별 SEQ 재사용, 같은 ACK 3회", false_positives=["순서 뒤바뀜(reordering)이 많은 경로"], environments=["모든 환경"], limits=["캡처 지점 이후의 손실만 추정"]),
    dict(type="connection_failure", label="서버 연결 중단", category="quality", basis="packet",
         condition="이전에 연결에 성공했던 (서버, 포트)로 보낸 SYN이 응답 없이 연속 {conn_fail_attempts}회 이상",
         thresholds=["conn_fail_attempts", "window_sec"], severity="주의~위험", certainty="measured",
         evidence="마지막 성공 이후 연속 실패 횟수, RST 수", false_positives=["서버 점검·재부팅"], environments=["내부 서버·NAS 사용 환경"], limits=["처음 접속하는 서버는 대상이 아님(성공 이력 필요)"]),
    dict(type="bandwidth_limit_suspect", label="대역폭 제한 의심", category="quality", basis="packet",
         condition="주요 흐름 처리량의 변동계수가 {bw_flat_cv:g} 이하로 평평하고({bw_min_seconds}초 이상) RTT가 평소보다 {bw_rtt_inflation_ms:g}ms 이상 증가",
         thresholds=["bw_flat_cv", "bw_min_seconds", "bw_rtt_inflation_ms"], severity="정보 (확정 불가)", certainty="suspected",
         evidence="초당 흐름 바이트, RTT 기준선", false_positives=["원래 그 속도인 회선", "상대 서버의 속도 제한"], environments=["대용량 전송 중"], limits=["QoS·회선 한계·서버 제한을 구분할 수 없음"]),
    dict(type="packet_size_anomaly", label="비정상 패킷 크기 의심", category="attack", basis="packet",
         condition="{window_sec}초 동안 페이로드 {size_anomaly_bytes}바이트 이상인 ICMP 또는 DNS 패킷이 {size_anomaly_min_count}개 이상",
         thresholds=["size_anomaly_bytes", "size_anomaly_min_count", "window_sec"], severity="정보 (확정 불가)", certainty="suspected",
         evidence="프로토콜별 대형 패킷 수", false_positives=["MTU 측정 도구(ping -s)", "DNSSEC·대형 TXT 응답"], environments=["모든 환경"], limits=["터널링을 확정하려면 페이로드 분석이 필요(미구현)"]),
    dict(type="proto_ratio_shift", label="프로토콜 비율 이상", category="usage", basis="statistical",
         condition="60초 이상 학습한 평소 비율 대비 UDP/ICMP/기타 비율이 {proto_shift_delta:.0%}p 이상 증가 (윈도우 평균 {proto_shift_min_pps} PPS 이상)",
         thresholds=["proto_shift_delta", "proto_shift_min_pps", "window_sec"], severity="정보", certainty="suspected",
         evidence="초 단위 프로토콜 비율 EWMA(이상 구간 제외)", false_positives=["영상통화·게임 시작(UDP)", "핑 테스트(ICMP)"], environments=["사용 패턴이 일정한 환경"], limits=["그 자체로는 문제가 아니라 참고 신호"]),
    dict(type="dns_nxdomain_surge", label="존재하지 않는 도메인 조회 급증", category="dns", basis="packet",
         condition="{window_sec}초 동안 NXDOMAIN 응답 {nxdomain_threshold}건 이상이고 서로 다른 도메인 {nxdomain_min_names}개 이상",
         thresholds=["nxdomain_threshold", "nxdomain_min_names", "window_sec"], severity="정보 (확정 불가)", certainty="suspected",
         evidence="NXDOMAIN 응답 수, 도메인 수, 예시 도메인", false_positives=["검색 도메인 설정으로 인한 접미사 질의", "광고 차단 DNS(NXDOMAIN으로 차단)"], environments=["평문 DNS 사용 환경"], limits=["DGA(도메인 생성 알고리즘) 여부는 도메인 모양을 봐야 하며 자동 판정하지 않음"]),
]

BASIS_KO = {"packet": "패킷 관측", "statistical": "통계 기준선", "probe": "ping·DNS 실측"}
CATEGORY_KO = {"attack": "공격 패턴", "usage": "사용량·트래픽", "quality": "품질·장애", "dns": "DNS", "spoof": "위조 의심"}
CERTAINTY_KO = {"suspected": "의심 (확정할 수 없음)", "likely": "가능성 높음", "measured": "측정값 기반"}


def rule_catalog(cfg: DetectionConfig) -> list[dict]:
    """현재 설정값을 채운 규칙 목록."""
    vals = {k: getattr(cfg, k) for k in vars(cfg)}
    out = []
    for r in RULES:
        d = dict(r)
        try:
            d["condition"] = r["condition"].format(**vals)
        except (KeyError, ValueError):
            d["condition"] = r["condition"]
        d["thresholds"] = [{"key": k, "value": vals.get(k)} for k in r["thresholds"]]
        d["basis_label"] = BASIS_KO.get(r["basis"], r["basis"])
        d["category_label"] = CATEGORY_KO.get(r["category"], r["category"])
        d["certainty_label"] = CERTAINTY_KO.get(r["certainty"], r["certainty"])
        out.append(d)
    return out
