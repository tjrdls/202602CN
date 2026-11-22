"""문제 진단: 원인 분석 + 자연어 설명 + 해결 방법 추천 (규칙 기반, AI 불필요).

각 이상 징후 유형마다
- title: 초보자용 제목
- summary: 쉬운 문장 설명
- technical: 전문가용 원문 설명
- analysis: 무엇이/누가/어떤 프로토콜/왜/영향
- false_positive: 오탐 가능성 안내
- recommendations: 실제로 관련 있는 조치만 (actions.py 의 action id 와 연결)
"""
from __future__ import annotations

from netcare.analysis import terms
from netcare.detection.detector import SEVERITY_KO

TYPE_LABELS = {
    "ip_packet_flood": "특정 장치의 과도한 패킷",
    "syn_surge": "새로운 연결 요청 급증",
    "port_concentration": "특정 포트 집중",
    "traffic_surge": "네트워크 사용량 급증",
    "repeated_connection": "반복되는 연결 시도",
    "port_scan": "여러 포트 탐색 패턴",
    "heavy_peer": "특정 장치와의 과도한 통신",
    "dns_failure": "도메인 주소 조회(DNS) 실패",
    "gateway_unreachable": "공유기(게이트웨이) 연결 끊김",
    "packet_loss": "데이터 손실 발생",
    "high_latency": "네트워크 지연",
}


def _who(ip: str | None, ctx: dict) -> str:
    return terms.describe_ip(ip, ctx.get("local_ips"), ctx.get("names"))


def _full(label: str, ip: str | None) -> str:
    """'외부 인터넷(1.2.3.4)' 처럼 이미 IP 가 들어 있으면 다시 붙이지 않는다."""
    if not ip or ip in label:
        return label
    return f"{label} ({ip})"


def _rec(action: str, title: str, why: str, **params) -> dict:
    return {"action": action, "title": title, "why": why, "params": params}


def _ip_recs(ip: str | None, ctx: dict, allow_block: bool = True) -> list[dict]:
    """의심 IP 관련 공통 추천. 내 컴퓨터/보호 대상이면 차단은 추천하지 않는다."""
    if not ip:
        return []
    recs = [_rec("inspect_ip", "이 장치와의 통신 내역 보기", "언제부터 어떤 서비스로 얼마나 통신했는지 확인해요.", ip=ip),
            _rec("find_process", "이 통신을 하는 프로그램 찾기", "내 컴퓨터의 어떤 프로그램이 관련됐는지 확인해요.", ip=ip)]
    local = ctx.get("local_ips") or set()
    if allow_block and ip not in local and terms.ip_scope(ip) != "special":
        recs.append(_rec("block_ip", "이 장치를 방화벽으로 차단 검토", "확인 결과 원치 않는 통신이면 방화벽으로 막을 수 있어요. 언제든 되돌릴 수 있어요.", ip=ip))
    return recs


def explain(a: dict, ctx: dict) -> dict:
    t = a["type"]
    ev = a.get("evidence") or {}
    sev = a["severity"]
    src, dst, port = a.get("src"), a.get("dst"), a.get("port")
    who_src, who_dst = _who(src, ctx), _who(dst, ctx)
    local = ctx.get("local_ips") or set()
    fn = _EXPLAINERS.get(t)
    if fn is None:
        base = {"title": TYPE_LABELS.get(t, t), "summary": "알 수 없는 유형의 이상 징후예요.", "technical": str(ev),
                "analysis": {}, "false_positive": "", "recommendations": []}
    else:
        base = fn(a, ev, ctx, who_src, who_dst, local)
    base["type_label"] = TYPE_LABELS.get(t, t)
    base["severity_label"] = SEVERITY_KO.get(sev, sev)
    base["certainty"] = ev.get("certainty")
    base["certainty_label"] = CERTAINTY_KO.get(ev.get("certainty"), "") if ev.get("certainty") else ""
    base["source_note"] = ("테스트 데이터에서 탐지된 결과예요. 실제 네트워크 상황이 아니에요."
                           if a.get("source") == "test" else
                           "가상 실험실(합성 데이터)에서 탐지된 결과예요. 실제 네트워크 상황이 아니에요."
                           if a.get("source") == "sim" else
                           ("pcap 파일 분석에서 탐지된 결과예요. 지금 진행 중인 상황이 아닐 수 있어요." if a.get("source") == "pcap" else ""))
    return base


def _ip_flood(a, ev, ctx, who_src, who_dst, local):
    pps, th = a["measured"], a["threshold"]
    bidir = ev.get("bidirectional")
    impact = "네트워크 대역폭을 많이 차지해서 다른 인터넷 사용이 느려질 수 있어요."
    fp = ("상대 장치도 활발하게 응답하고 있어요(양방향 통신). 대용량 다운로드, 동영상 스트리밍, 백업처럼 정상적인 활동일 가능성이 높아요."
          if bidir else "상대방의 응답이 거의 없는 한쪽 방향 통신이에요. 정상 프로그램일 수도 있지만, 의도하지 않은 대량 전송인지 확인이 필요해요.")
    recs = []
    if a["src"] in local:
        recs.append(_rec("find_process", "패킷을 많이 보내는 프로그램 찾기", "내 컴퓨터의 어떤 프로그램이 패킷을 보내는지 확인해요.",
                         ip=ev.get("top_peer") or ""))
    else:
        recs += _ip_recs(a["src"], ctx, allow_block=not bidir)
    recs.append(_rec("connectivity_check", "인터넷 연결 상태 점검", "다른 통신이 영향을 받고 있는지 지연과 손실을 측정해요."))
    return {
        "title": f"{who_src}에서 데이터가 아주 많이 오가고 있어요",
        "summary": f"{who_src}이(가) 1초에 약 {pps:,.0f}개의 패킷을 보내고 있어요. 기준({th:,.0f}개)보다 {pps / th:.1f}배 많아요. "
                   + ("정상적인 대용량 전송일 가능성이 있지만, 계속된다면 어떤 프로그램인지 확인해 보세요." if bidir
                      else "평소와 다른 한쪽 방향 대량 전송이라 확인이 필요해요."),
        "technical": f"src={a['src']} {pps:.1f} pps over {ev.get('window_sec')}s (threshold {th:g}); top peer={ev.get('top_peer')}, "
                     f"reverse ratio={ev.get('reverse_ratio')}",
        "analysis": {"what": "특정 IP의 초당 패킷 수가 기준치를 넘었어요.", "who": f"{_full(who_src, a['src'])} → {who_dst}",
                     "protocol": "여러 프로토콜(패킷 수 기준)",
                     "why": f"{ev.get('window_sec')}초 동안 {ev.get('packets'):,}개, 초당 {pps:,.1f}개 (기준 {th:,.0f}개)",
                     "impact": impact},
        "false_positive": fp, "recommendations": recs,
    }


def _syn(a, ev, ctx, who_src, who_dst, local):
    n, success = ev.get("syn", 0), ev.get("success_ratio", 0)
    W = ev.get("window_sec")
    if ev.get("distributed"):
        return {
            "title": f"{who_dst}에 여러 곳에서 연결 요청이 몰리고 있어요",
            "summary": f"{W}초 동안 서로 다른 {ev.get('distinct_sources')}개 주소에서 {who_dst}로 새 연결 요청이 {n}번 들어왔는데, "
                       f"연결이 끝까지 완료된 건 {success:.0%}뿐이에요. 여러 출발지를 이용한 연결 폭주(분산 SYN Flood)와 비슷한 패턴이에요.",
            "technical": f"SYN to {a['dst']}: {n} from {ev.get('distinct_sources')} sources in {W}s, handshake completed {ev.get('completed')}",
            "analysis": {"what": "한 장치로 향하는 TCP 연결 요청이 여러 출발지에서 급증했어요.", "who": f"대상: {_full(who_dst, a['dst'])}",
                         "protocol": "TCP (3-way handshake)", "why": f"SYN {n}개 (기준 {a['threshold']:.0f}개), 출발지 {ev.get('distinct_sources')}개, 완료율 {success:.0%}",
                         "impact": "대상 장치의 연결 대기열이 가득 차서 정상 사용자의 접속이 거부될 수 있어요."},
            "false_positive": "인기 있는 서버를 운영 중이라면 많은 사용자가 동시에 접속할 때도 비슷하게 보일 수 있어요. 완료율이 낮다는 점이 핵심 근거예요.",
            "recommendations": [_rec("inspect_ip", "대상 장치의 통신 내역 보기", "어떤 서비스로 요청이 몰리는지 확인해요.", ip=a["dst"]),
                                _rec("connectivity_check", "인터넷 연결 상태 점검", "연결 품질에 영향이 있는지 측정해요.")],
        }
    is_me = a["src"] in local
    replied = ev.get("syn_ack", 0)
    if replied and success < 0.3:
        pattern = f"상대는 {replied}번 응답(SYN-ACK)했지만 요청한 쪽이 연결을 끝맺지 않았어요(마지막 ACK 없음). SYN Flood에서 자주 보이는 형태예요."
    elif ev.get("rst_received"):
        pattern = f"상대가 {ev['rst_received']}번 연결을 거부(RST)했어요. 닫힌 포트에 계속 연결을 시도하고 있어요."
    else:
        pattern = "상대의 응답이 거의 없어요."
    recs = []
    if is_me:
        recs.append(_rec("find_process", "연결 요청을 보내는 프로그램 찾기", "내 컴퓨터의 어떤 프로그램이 연결을 계속 시도하는지 확인해요."))
        recs.append(_rec("connectivity_check", "인터넷 연결 상태 점검", "연결이 실패하는 원인이 네트워크 문제인지 확인해요."))
    else:
        recs += _ip_recs(a["src"], ctx)
    return {
        "title": "새로운 연결 요청이 평소보다 많아졌어요",
        "summary": f"{who_src}에서 {W}초 동안 새 연결 요청을 {n}번 보냈는데, 연결이 끝까지 완료된 건 {success:.0%}뿐이에요. "
                   "정상적인 프로그램의 활동일 수도 있지만, 비정상적인 통신인지 확인할 필요가 있어요.",
        "technical": f"TCP SYN from {a['src']}: {n} in {W}s, handshake completed {ev.get('completed')} ({success:.0%}), "
                     f"SYN-ACK seen {replied}, RST {ev.get('rst_received')}",
        "analysis": {"what": "TCP 연결 요청(SYN)이 급증했고 대부분 연결이 완료되지 않았어요.",
                     "who": _full(who_src, a['src']), "protocol": "TCP (연결 시작 단계: 3-way handshake)",
                     "why": f"SYN {n}개 (기준 {a['threshold']:.0f}개), 연결 완료율 {success:.0%} (30% 미만이면 의심). {pattern}",
                     "impact": ("상대 서버나 공유기의 연결 자원을 소모시켜 서비스를 느리게 만들 수 있어요(SYN Flood 형태)."
                                if not is_me else "응답하지 않거나 거부하는 서버에 계속 연결을 시도하고 있어요. 프로그램 오류나 네트워크 차단일 수 있어요.")},
        "false_positive": "응답이 늦거나 막힌 서버에 프로그램이 재시도하는 경우, 네트워크 스캐너/모니터링 도구를 쓰는 경우에도 같은 패턴이 나올 수 있어요.",
        "recommendations": recs,
    }


def _port_conc(a, ev, ctx, who_src, who_dst, local):
    svc = ev.get("service") or f"{a['protocol']}/{a['port']}"
    desc = terms.service_for(a["protocol"], a["port"], a["port"])[1]
    common = ev.get("common_service")
    return {
        "title": f"{desc}에 통신이 몰리고 있어요",
        "summary": f"최근 {ev.get('window_sec')}초 동안 전체 통신의 {ev.get('share', 0):.0%}가 {a['port']}번 포트({desc})로 오갔어요. "
                   + ("웹 서핑이나 동영상 시청처럼 흔한 활동이라 대개 정상이에요." if common else "흔히 쓰는 서비스 포트가 아니라서 어떤 프로그램인지 확인해 보세요."),
        "technical": f"port {a['protocol']}/{a['port']} ({svc}) = {ev.get('port_packets')}/{ev.get('total_packets')} packets "
                     f"({ev.get('share', 0):.1%}) in {ev.get('window_sec')}s",
        "analysis": {"what": "특정 포트로 트래픽이 집중됐어요.", "who": "여러 장치(포트 기준 집계)", "protocol": f"{a['protocol']} {a['port']} ({desc})",
                     "why": f"점유율 {ev.get('share', 0):.0%} (기준 {a['threshold']:.0%}), 패킷 {ev.get('total_packets'):,}개",
                     "impact": "해당 서비스가 대역폭을 독점하면 다른 서비스가 느려질 수 있어요."},
        "false_positive": "443(HTTPS), 80(HTTP), 53(DNS)은 원래 통신량이 많은 포트예요. 이런 포트는 '정보' 등급으로만 표시해요.",
        "recommendations": [_rec("find_process", f"{a['port']}번 포트를 쓰는 프로그램 찾기", "어떤 프로그램이 이 포트로 통신하는지 확인해요.", port=a["port"]),
                            _rec("connectivity_check", "인터넷 연결 상태 점검", "다른 통신이 느려졌는지 측정해요.")],
    }


def _surge(a, ev, ctx, who_src, who_dst, local):
    cur = ev.get("current_bps", a["measured"])
    if ev.get("method") == "EWMA z-score":
        why = f"평소 평균 {terms.human_rate(ev['baseline_mean_bps'])} → 현재 {terms.human_rate(cur)} (z-score {ev['z_score']}, 기준 {ctx.get('z', 4)})"
    else:
        why = f"현재 {terms.human_rate(cur)} (학습 전 고정 기준 {terms.human_rate(a['threshold'])})"
    return {
        "title": "네트워크 사용량이 갑자기 증가했어요",
        "summary": f"지금 네트워크 사용량이 {terms.human_rate(cur)}로 평소보다 크게 늘었어요. "
                   "업데이트, 클라우드 동기화, 대용량 다운로드처럼 정상적인 이유가 많아요. 직접 실행한 작업이 없다면 어떤 프로그램인지 확인해 보세요.",
        "technical": f"throughput {cur:.0f} B/s; {ev}",
        "analysis": {"what": "전체 트래픽이 기준선보다 급격히 증가했어요(Traffic Spike).", "who": "전체 네트워크",
                     "protocol": "전체", "why": why,
                     "impact": "인터넷이 느려지고, 데이터 요금제라면 사용량이 늘 수 있어요."},
        "false_positive": "기준선은 이 프로그램이 지켜본 최근 시간만으로 학습돼요. 관찰 시간이 짧으면 평범한 다운로드도 '급증'으로 보일 수 있어요.",
        "recommendations": [_rec("find_process", "통신량이 많은 프로그램 찾기", "지금 네트워크를 쓰는 프로그램 목록을 확인해요."),
                            _rec("connectivity_check", "인터넷 연결 상태 점검", "지연과 손실이 생겼는지 측정해요.")],
    }


def _repeat(a, ev, ctx, who_src, who_dst, local):
    rst = ev.get("rst_received", 0)
    svc = terms.service_for("TCP", a["port"] or 0, a["port"] or 0)[1]
    refused = rst > 0
    recs = []
    if a["src"] in local:
        recs.append(_rec("find_process", "연결을 반복하는 프로그램 찾기", "어떤 프로그램이 같은 곳에 계속 연결을 시도하는지 확인해요.", ip=a["dst"] or ""))
        recs.append(_rec("connectivity_check", "연결 상태 점검", "상대 서버까지의 경로에 문제가 없는지 확인해요.", target=a["dst"] or ""))
    else:
        recs += _ip_recs(a["src"], ctx)
    return {
        "title": "같은 곳에 연결을 반복해서 시도하고 있어요",
        "summary": f"{who_src}이(가) {who_dst}의 {a['port']}번 포트({svc})에 {ev.get('window_sec')}초 동안 {a['measured']}번 연결을 시도했어요. "
                   + ("상대가 연결을 거부하고 있어서(RST) 프로그램이 계속 재시도하는 것 같아요." if refused else "응답이 없어서 재시도하고 있을 수 있어요."),
        "technical": f"{a['src']} → {a['dst']}:{a['port']} SYN x{a['measured']} in {ev.get('window_sec')}s; RST received {rst}",
        "analysis": {"what": "짧은 시간에 같은 목적지로 연결 요청이 반복됐어요.", "who": f"{who_src} → {who_dst}",
                     "protocol": f"TCP {a['port']} ({svc})", "why": f"{a['measured']}회 (기준 {a['threshold']:.0f}회)",
                     "impact": "서비스가 꺼져 있거나 막혀 있다는 신호일 수 있고, 로그인 대입 공격(무차별 대입)일 때도 이런 패턴이 나와요."},
        "false_positive": "서버 점검 중이거나 방화벽에 막힌 서비스에 앱이 자동으로 재접속을 시도하는 경우가 흔해요.",
        "recommendations": recs,
    }


def _scan(a, ev, ctx, who_src, who_dst, local):
    is_me = a["src"] in local
    recs = []
    if is_me:
        recs.append(_rec("find_process", "탐색을 하는 프로그램 찾기", "내 컴퓨터의 어떤 프로그램이 여러 곳에 연결을 시도하는지 확인해요."))
    else:
        recs += _ip_recs(a["src"], ctx)
    return {
        "title": "여러 포트를 차례로 두드리는 패턴이 보여요",
        "summary": f"{who_src}이(가) {ev.get('window_sec')}초 동안 서로 다른 {ev.get('distinct_targets')}곳(장치 {ev.get('distinct_hosts')}개, 포트 {ev.get('distinct_ports')}개)에 연결을 시도했어요. "
                   "열려 있는 서비스를 찾는 '포트 스캔'과 비슷한 패턴이에요.",
        "technical": f"{a['src']} contacted {ev.get('distinct_targets')} distinct (host,port) pairs; pattern={ev.get('pattern')}; ports={ev.get('sample_ports')}",
        "analysis": {"what": "한 장치가 짧은 시간에 많은 목적지·포트로 연결을 시도했어요.", "who": _full(who_src, a['src']),
                     "protocol": "TCP/UDP", "why": f"서로 다른 대상 {ev.get('distinct_targets')}곳 (기준 {a['threshold']:.0f}곳), 패턴: {ev.get('pattern')}",
                     "impact": "취약한 서비스를 찾는 사전 정찰일 수 있어요. 열린 포트가 노출되면 공격 대상이 될 수 있어요."},
        "false_positive": "공유기 관리 앱, 프린터·스마트기기 검색, 네트워크 관리 도구도 여러 장치에 접속을 시도해요. 직접 사용하는 도구인지 먼저 확인하세요.",
        "recommendations": recs,
    }


def _peer(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": f"{who_src}와(과)의 통신이 대부분을 차지해요",
        "summary": f"최근 {ev.get('window_sec')}초 동안 받은 데이터의 {ev.get('share', 0):.0%}가 {who_src}에서 왔어요 ({terms.human_rate(ev.get('rate_bps', 0))}). "
                   "대개 동영상, 다운로드, 클라우드 동기화 때문이에요.",
        "technical": f"{a['src']} bytes share {ev.get('share', 0):.1%}, {ev.get('rate_bps', 0):.0f} B/s",
        "analysis": {"what": "특정 IP와의 통신량이 매우 많아요.", "who": _full(who_src, a['src']), "protocol": "전체",
                     "why": f"점유율 {ev.get('share', 0):.0%} (기준 {a['threshold']:.0%})", "impact": "다른 통신이 느려질 수 있어요."},
        "false_positive": "직접 실행한 다운로드나 스트리밍이라면 정상이에요.",
        "recommendations": _ip_recs(a["src"], ctx, allow_block=False)
                           + [_rec("connectivity_check", "인터넷 연결 상태 점검", "다른 통신이 영향을 받는지 측정해요.")],
    }


def _dns(a, ev, ctx, who_src, who_dst, local):
    names = ", ".join(ev.get("failed_names") or []) or "여러 도메인"
    server = ev.get("dns_server")
    return {
        "title": "웹사이트 주소를 찾지 못하고 있어요",
        "summary": f"도메인 주소 조회(DNS)가 {ev.get('queries', 0)}건 중 {ev.get('error_responses', 0) + ev.get('unanswered', 0)}건 실패했어요 ({names}). "
                   "인터넷은 연결돼 있어도 사이트가 안 열리는 현상이 생길 수 있어요.",
        "technical": f"DNS failures: errors={ev.get('error_responses')} unanswered={ev.get('unanswered')} of {ev.get('queries')} queries; server={server}",
        "analysis": {"what": "DNS 질의가 오류로 응답되거나 응답이 없었어요.", "who": f"DNS 서버 {server or '(알 수 없음)'}",
                     "protocol": "DNS (UDP 53)", "why": f"실패 {ev.get('error_responses', 0) + ev.get('unanswered', 0)}건, 실패율 {ev.get('failure_ratio', 0):.0%}",
                     "impact": "웹사이트·앱이 '서버를 찾을 수 없음' 오류를 낼 수 있어요."},
        "false_positive": "존재하지 않는 주소를 일부러 조회하는 프로그램(광고 차단기, 보안 프로그램)이 있으면 오류 응답이 늘 수 있어요."
                          + (f" 참고로 같은 도메인의 다른 질의는 성공한 무응답 {ev['partial_unanswered']}건(예: IPv6 주소 AAAA 질의)은 사이트 접속에 영향이 없어서 실패에서 뺐어요."
                             if ev.get("partial_unanswered") else ""),
        "recommendations": [_rec("dns_test", "DNS 조회 테스트", "주요 사이트 주소가 정상적으로 조회되는지 직접 확인해요."),
                            _rec("flush_dns", "DNS 캐시 초기화", "잘못 저장된 주소 정보를 지우고 새로 조회하게 해요."),
                            _rec("connectivity_check", "인터넷 연결 상태 점검", "DNS 문제인지 인터넷 자체 문제인지 구분해요.")],
    }


def _gateway(a, ev, ctx, who_src, who_dst, local):
    loss = ev.get("loss_pct", 0)
    return {
        "title": "공유기와의 연결이 불안정해요" if a["type"] != "gateway_unreachable" else "공유기와 연결되지 않아요",
        "summary": f"공유기({ev.get('target')})에 보낸 확인 신호 {ev.get('sent')}개 중 {ev.get('received')}개만 돌아왔어요 (손실 {loss:g}%). "
                   "데이터 전달 과정에서 일부 손실이 발생하고 있어요.",
        "technical": f"ICMP echo to {ev.get('target')}: {ev.get('received')}/{ev.get('sent')} replies, loss {loss}%",
        "analysis": {"what": "공유기까지의 연결에서 패킷 손실(Packet Loss)이 생겼어요.", "who": f"공유기 {ev.get('target')}",
                     "protocol": "ICMP (연결 상태 확인 통신)", "why": f"손실률 {loss:g}% (기준 {a['threshold']:g}%)",
                     "impact": "인터넷이 끊기거나 매우 느려질 수 있어요."},
        "false_positive": "일부 공유기는 ping에 응답하지 않도록 설정돼 있어요. 인터넷이 잘 된다면 그 경우일 수 있어요.",
        "recommendations": [_rec("connectivity_check", "연결 상태 다시 측정", "공유기와 인터넷까지 단계별로 다시 확인해요."),
                            {"action": None, "title": "Wi-Fi 신호와 케이블 확인", "why": "공유기와 가까운 곳으로 옮기거나 랜선이 잘 꽂혀 있는지 확인하세요. 문제가 계속되면 공유기를 재시작해 보세요(안내만 제공, 자동 실행 안 함).", "params": {}}],
    }


def _loss(a, ev, ctx, who_src, who_dst, local):
    if "gateway_ok" not in ev:
        return _gateway(a, ev, ctx, who_src, who_dst, local)
    loss = ev.get("loss_pct", 0)
    return {
        "title": "데이터 전달 과정에서 일부 손실이 발생했어요",
        "summary": f"외부 인터넷({ev.get('target')})으로 보낸 확인 신호의 {loss:g}%가 돌아오지 않았어요. "
                   + ("공유기까지는 정상이라 인터넷 회선(통신사) 쪽 문제일 가능성이 있어요." if ev.get("gateway_ok") else "공유기 연결부터 확인이 필요해요."),
        "technical": f"ICMP echo to {ev.get('target')}: {ev.get('received')}/{ev.get('sent')}, loss {loss}%",
        "analysis": {"what": "인터넷 구간에서 패킷 손실이 생겼어요.", "who": f"외부 대상 {ev.get('target')}", "protocol": "ICMP",
                     "why": f"손실률 {loss:g}% (기준 {a['threshold']:g}%)", "impact": "화상통화 끊김, 게임 지연, 페이지 로딩 실패가 생길 수 있어요."},
        "false_positive": "측정 대상 서버가 ping 응답을 제한할 수도 있어요. 다른 대상으로 다시 측정해 보세요.",
        "recommendations": [_rec("connectivity_check", "연결 상태 다시 측정", "공유기·인터넷 구간을 나눠서 다시 확인해요.")],
    }


def _latency(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": "네트워크 응답이 느려요",
        "summary": f"{ev.get('target')}까지 응답 시간이 평균 {ev.get('avg_ms')}ms예요 (기준 {a['threshold']:g}ms). 웹페이지가 늦게 열리거나 게임·통화가 끊길 수 있어요.",
        "technical": f"RTT avg {ev.get('avg_ms')}ms max {ev.get('max_ms')}ms to {ev.get('target')}",
        "analysis": {"what": "왕복 지연 시간(RTT)이 길어요.", "who": f"{ev.get('target')}", "protocol": "ICMP",
                     "why": f"평균 {ev.get('avg_ms')}ms (기준 {a['threshold']:g}ms)", "impact": "실시간 서비스 품질이 떨어져요."},
        "false_positive": "같은 네트워크에서 대용량 다운로드가 진행 중이면 일시적으로 지연이 커질 수 있어요.",
        "recommendations": [_rec("connectivity_check", "지연·손실 다시 측정", "지연이 계속되는지 확인해요."),
                            _rec("find_process", "통신량이 많은 프로그램 찾기", "대역폭을 많이 쓰는 프로그램이 원인일 수 있어요.")],
    }


_EXPLAINERS = {
    "ip_packet_flood": _ip_flood, "syn_surge": _syn, "port_concentration": _port_conc, "traffic_surge": _surge,
    "repeated_connection": _repeat, "port_scan": _scan, "heavy_peer": _peer, "dns_failure": _dns,
    "gateway_unreachable": _gateway, "packet_loss": _loss, "high_latency": _latency,
}


# ───────────────────────── 확장 규칙 설명 (스푸핑 의심 · 연결 품질) ─────────────────────────
TYPE_LABELS.update({
    "arp_spoof": "ARP 스푸핑 의심",
    "ip_spoof_suspect": "IP 스푸핑(출발지 위조) 의심",
    "dns_spoof_suspect": "DNS 응답 위조 의심",
    "latency_rise": "네트워크 지연 증가",
    "jitter_high": "지연 시간 불규칙(지터)",
    "tcp_loss": "데이터 손실(재전송 증가)",
    "connection_failure": "서버 연결 중단",
    "bandwidth_limit_suspect": "대역폭 제한 의심",
})

TYPE_LABELS.update({
    "packet_size_anomaly": "비정상 패킷 크기 의심",
    "checksum_error": "체크섬 오류 (손상·변조 패킷 의심)",
    "tcp_injection": "TCP 주입 의심 (RST·데이터)",
    "udp_replay": "UDP 재전송(리플레이) 의심",
    "web_attack": "웹 공격 시도 (HTTP)",
    "web_scan": "웹 탐색·크롤링 (HTTP)",
    "auth_bruteforce": "로그인 무차별 대입",
    "proto_ratio_shift": "프로토콜 비율 이상",
    "dns_nxdomain_surge": "존재하지 않는 도메인 조회 급증",
})

CERTAINTY_KO = {"suspected": "의심 (확정할 수 없음)", "likely": "가능성 높음", "measured": "측정값 기반"}


def _arp(a, ev, ctx, who_src, who_dst, local):
    gw = ev.get("is_gateway")
    return {
        "title": "공유기 주소를 사칭하는 장치가 의심돼요 (ARP 스푸핑 의심)" if gw else "같은 네트워크에서 주소 사칭이 의심돼요 (ARP 스푸핑 의심)",
        "summary": f"{ev.get('target_ip')} 주소의 하드웨어(MAC) 주소가 짧은 시간에 {len(ev.get('macs', []))}개로 바뀌었어요 "
                   f"(의심 MAC {ev.get('suspect_mac')}). "
                   + ("다른 장치가 공유기인 척하며 내 데이터를 가로채려는 '중간자 공격'의 대표적인 징후예요." if gw else
                      "다른 장치가 이 주소를 사칭하고 있을 수 있어요.")
                   + (f" 실제로 내 컴퓨터가 의심 MAC으로 보낸 데이터가 {ev['redirected_frames']}개 있어요." if ev.get("redirected_frames") else ""),
        "technical": f"ARP binding change for {ev.get('target_ip')}: macs={ev.get('macs')} conflicts={ev.get('conflicts')} "
                     f"unsolicited replies={ev.get('unsolicited_replies')} frames→suspect={ev.get('redirected_frames')}",
        "analysis": {"what": "IP-MAC 대응 관계(ARP)가 반복해서 바뀌었어요.", "who": f"대상 {ev.get('target_ip')}, 의심 MAC {ev.get('suspect_mac')}",
                     "protocol": "ARP (같은 네트워크에서 장치 주소 확인)",
                     "why": f"MAC 변경 {ev.get('conflicts')}회 (기준 2회), 요청 없는 ARP 응답 {ev.get('unsolicited_replies')}회",
                     "impact": "통신이 공격자 장치를 거쳐 가면서 엿보기·변조·끊김이 생길 수 있어요."},
        "false_positive": "공유기 교체, IP 재할당(DHCP), 공유기 이중화(VRRP), Wi-Fi 확장기·브리지 장비도 MAC 변경을 일으킬 수 있어요.",
        "recommendations": [
            {"action": None, "title": "공유기 관리 화면에서 접속 장치 목록 확인", "why": f"의심 MAC {ev.get('suspect_mac')}이 어떤 장치인지 확인하세요. 모르는 장치라면 Wi-Fi 비밀번호를 바꾸세요.", "params": {}},
            {"action": None, "title": "공유기 MAC을 정적 ARP로 고정 (고급)", "why": "검증된 공유기 MAC을 고정하면 사칭 응답을 무시해요. 잘못 설정하면 인터넷이 끊길 수 있어 안내만 제공해요.", "params": {}},
            _rec("connectivity_check", "연결 상태 점검", "지연·끊김이 생겼는지 측정해요."),
        ],
    }


def _ip_spoof(a, ev, ctx, who_src, who_dst, local):
    ind = ev.get("indicators") or {}
    names = {"own_ip": "내 주소를 출발지로 쓴 외부 프레임", "bogon": "사용될 수 없는 예약 주소 출발지", "lan_mac_mismatch": "같은 네트워크 장치 IP인데 MAC이 다름",
             "ttl": "평소와 크게 다른 TTL(경로 길이)", "backscatter": "요청한 적 없는 연결 수락(SYN-ACK) 응답"}
    lines = ", ".join(f"{names.get(k, k)} {v}건" for k, v in ind.items())
    return {
        "title": "출발지 주소가 위조된 패킷이 의심돼요 (IP 스푸핑 의심)",
        "summary": f"최근 {ev.get('window_sec')}초 동안 출발지 주소가 조작됐을 때 나타나는 징후가 {a['measured']}건 보였어요({lines}). "
                   "패킷만 보고는 위조를 확정할 수 없어서 '의심'으로 알려드려요. 위조된 주소는 진짜 보낸 곳이 아니라서, 그 IP를 차단해도 효과가 거의 없어요.",
        "technical": f"spoof indicators={ind}, sources={ev.get('sample_sources')} ({ev.get('distinct_sources')} distinct), frame MACs={ev.get('frame_macs')}",
        "analysis": {"what": "출발지 IP 주소 조작이 의심되는 패킷이 반복됐어요.",
                     "who": f"출발지(위조 가능) {ev.get('distinct_sources')}개, 실제 전달한 MAC {', '.join(ev.get('frame_macs') or []) or '-'}",
                     "protocol": "IP 계층", "why": f"위조 징후 {a['measured']}건 (기준 {a['threshold']:.0f}건): {lines}",
                     "impact": "위조 주소는 연결 폭주 공격(DDoS)이나 추적 회피에 쓰여요. 내 주소가 도용되면 남을 공격한 것처럼 보일 수 있어요."},
        "false_positive": "경로 변경으로 TTL이 바뀌거나, 캡처 시작 직전에 보낸 요청의 응답(SYN-ACK)이 늦게 도착할 때도 일부 징후가 나타나요.",
        "recommendations": [
            {"action": None, "title": "위조 출발지 차단(인그레스 필터링) 검토", "why": "공유기·방화벽에서 '내 대역이나 예약 주소를 출발지로 한 외부 패킷 거부' 규칙을 켜는 것이 근본 대응이에요 (안내만 제공).", "params": {}},
            {"action": None, "title": "프레임을 보낸 MAC 확인", "why": f"IP는 위조돼도 같은 네트워크에서는 실제 MAC이 보여요: {', '.join(ev.get('frame_macs') or []) or '-'}", "params": {}},
            _rec("connectivity_check", "연결 상태 점검", "공격으로 연결 품질이 떨어졌는지 측정해요."),
        ],
    }


def _dns_spoof(a, ev, ctx, who_src, who_dst, local):
    ind = ev.get("indicators") or {}
    names = {"conflict": "같은 질의에 서로 다른 응답", "wrong_server": "질의하지 않은 서버의 응답", "server_mac": "DNS 서버 MAC 변경"}
    lines = ", ".join(f"{names.get(k, k)} {v}건" for k, v in ind.items())
    return {
        "title": "DNS 응답이 조작됐을 수 있어요 (DNS 위조 의심)",
        "summary": f"웹사이트 주소 조회 응답에서 조작 징후가 {a['measured']}건 보였어요({lines}). "
                   f"관련 도메인: {', '.join(ev.get('names') or []) or '-'}. 가짜 사이트로 유도될 수 있으니, 로그인이나 결제는 잠시 미루세요.",
        "technical": f"DNS spoof indicators={ind}, examples={ev.get('examples')}",
        "analysis": {"what": "DNS 응답이 경합하거나 엉뚱한 곳에서 왔어요.", "who": f"도메인 {', '.join(ev.get('names') or []) or '-'}",
                     "protocol": "DNS (UDP 53)", "why": f"위조 징후 {a['measured']}건 (기준 {a['threshold']:.0f}건): {lines}",
                     "impact": "피싱 사이트 접속, 계정 정보 유출로 이어질 수 있어요."},
        "false_positive": "같은 질의를 다시 보냈을 때 서버가 다른 IP 순서/조합으로 응답하는 CDN, 여러 DNS 서버를 동시에 쓰는 설정에서도 일부 징후가 생길 수 있어요. "
                          "처음부터 위조된 응답 하나만 온 경우는 패킷만으로 구분할 수 없어요(DNSSEC가 없으면 원리적 한계).",
        "recommendations": [_rec("dns_test", "DNS 조회 테스트", "주요 사이트 주소를 다시 조회해 비교해요."),
                            _rec("flush_dns", "DNS 캐시 초기화", "조작된 응답이 저장돼 있다면 지워요."),
                            {"action": None, "title": "암호화 DNS(DoH/DoT) 사용 검토", "why": "암호화된 DNS는 중간에서 응답을 끼워 넣을 수 없어요.", "params": {}}],
    }


def _lat(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": "네트워크 응답이 평소보다 느려졌어요",
        "summary": f"연결을 맺을 때와 주소 조회 때 걸리는 시간이 평소 {ev.get('baseline_ms')}ms에서 {ev.get('median_ms')}ms로 늘었어요. 웹페이지가 늦게 열리고 화상통화·게임이 끊길 수 있어요.",
        "technical": f"median RTT {ev.get('median_ms')}ms (baseline {ev.get('baseline_ms')}ms, n={ev.get('samples')}) via {ev.get('method')}",
        "analysis": {"what": "왕복 지연 시간(RTT)이 늘었어요.", "who": "여러 상대와의 통신(중앙값)", "protocol": "TCP 핸드셰이크·DNS",
                     "why": f"중앙값 {ev.get('median_ms')}ms (기준 {a['threshold']:g}ms, 평소 {ev.get('baseline_ms')}ms)", "impact": "실시간 서비스 품질이 떨어져요."},
        "false_positive": "멀리 있는 해외 서버 위주로 접속하면 정상이어도 RTT가 커요. 평소 기준선 대비로 판단하지만 사용 패턴이 바뀌면 오탐이 생길 수 있어요.",
        "recommendations": [_rec("connectivity_check", "구간별 지연 측정", "공유기 구간인지 인터넷 구간인지 나눠서 확인해요."),
                            _rec("find_process", "대역폭을 많이 쓰는 프로그램 찾기", "다른 프로그램의 대용량 전송이 원인일 수 있어요.")],
    }


def _jit(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": "응답 속도가 들쭉날쭉해요 (지터 증가)",
        "summary": f"같은 상대와 주고받는 응답 시간이 매번 평균 {ev.get('jitter_ms')}ms씩 달라지고 있어요 ({ev.get('min_ms')}~{ev.get('max_ms')}ms). 음성·화상 통화가 끊기거나 소리가 튈 수 있어요.",
        "technical": f"jitter (median |ΔRTT| per peer) {ev.get('jitter_ms')}ms over {ev.get('pairs')} pairs, baseline {ev.get('baseline_jitter_ms')}ms",
        "analysis": {"what": "지연 시간의 변동(지터)이 커졌어요.", "who": "여러 상대(상대별 연속 차이)", "protocol": "TCP 핸드셰이크·DNS",
                     "why": f"평균 변동 {ev.get('jitter_ms')}ms (기준 {a['threshold']:g}ms)", "impact": "실시간 서비스(통화·게임·스트리밍)가 불안정해져요."},
        "false_positive": "Wi-Fi 신호가 약하거나 다른 사람이 대용량 전송을 하면 일시적으로 생길 수 있어요.",
        "recommendations": [_rec("connectivity_check", "지연·손실 다시 측정", "변동이 계속되는지 확인해요."),
                            {"action": None, "title": "유선 연결 또는 공유기 가까이로 이동", "why": "무선 간섭이 지터의 흔한 원인이에요.", "params": {}}],
    }


def _loss2(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": "데이터 전달 과정에서 일부 손실이 발생했어요",
        "summary": f"최근 {ev.get('window_sec')}초 동안 데이터 {ev.get('data_segments')}개 중 다시 보내거나 빠졌다고 알린 경우가 {ev.get('retransmissions', 0) + ev.get('triple_dup_acks', 0)}건이에요 "
                   f"(약 {ev.get('tcp_loss_ratio', 0):.0%})" + (f", 확인 신호(ping) {ev.get('ping_sent')}개 중 {ev.get('ping_lost')}개가 돌아오지 않았어요." if ev.get("ping_sent") else ".")
                   + " 인터넷이 느려지거나 끊길 수 있어요.",
        "technical": f"retrans={ev.get('retransmissions')} triple-dupACK={ev.get('triple_dup_acks')} / segs={ev.get('data_segments')}; ping {ev.get('ping_lost')}/{ev.get('ping_sent')} lost",
        "analysis": {"what": "TCP 재전송과 중복 확인 응답이 늘었어요(Packet Loss).", "who": "전체 통신", "protocol": "TCP / ICMP",
                     "why": f"손실 지표 {a['measured']:.1%} (기준 {a['threshold']:.0%})", "impact": "속도 저하, 영상 끊김, 연결 실패가 생길 수 있어요."},
        "false_positive": "캡처 장비가 패킷을 놓쳐도 재전송처럼 보일 수 있어요. 화면의 '놓친 패킷' 수가 0인지 함께 확인하세요.",
        "recommendations": [_rec("connectivity_check", "구간별 손실 측정", "공유기 구간인지 인터넷 구간인지 나눠서 확인해요."),
                            {"action": None, "title": "케이블·Wi-Fi 신호 점검", "why": "손상된 케이블이나 약한 무선 신호가 손실의 흔한 원인이에요.", "params": {}}],
    }


def _connfail(a, ev, ctx, who_src, who_dst, local):
    svc = terms.service_for("TCP", a.get("port") or 0, a.get("port") or 0)[1]
    return {
        "title": "평소 연결되던 서버에 접속이 안 돼요",
        "summary": f"{who_dst}의 {a.get('port')}번 포트({svc})에 {ev.get('window_sec')}초 동안 {ev.get('attempts')}번 연결을 시도했지만 모두 실패했어요({ev.get('mode')}). "
                   f"{ev.get('last_success_ago_sec')}초 전까지는 정상적으로 연결됐어요.",
        "technical": f"{a.get('dst')}:{a.get('port')} SYN x{ev.get('attempts')} no SYN-ACK, RST {ev.get('refused_rst')}, last success {ev.get('last_success_ago_sec')}s ago",
        "analysis": {"what": "서버가 연결 요청에 응답하지 않거나 거부해요.", "who": _full(who_dst, a.get("dst")), "protocol": f"TCP {a.get('port')} ({svc})",
                     "why": f"실패 {ev.get('attempts')}회 (기준 {a['threshold']:.0f}회), 이전 성공 기록 있음", "impact": "해당 서비스를 사용할 수 없어요."},
        "false_positive": "서버 점검·재시작 중이거나, 서비스가 일부 지역에서만 막힌 경우에도 같은 현상이 보여요.",
        "recommendations": [_rec("connectivity_check", "서버까지 연결 점검", "내 쪽 문제인지 서버 쪽 문제인지 구분해요.", target=a.get("dst") or ""),
                            _rec("inspect_ip", "이 서버와의 통신 내역 보기", "언제부터 실패했는지 확인해요.", ip=a.get("dst") or "")],
    }


def _bw(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": "대역폭이 제한되고 있는 것 같아요 (의심)",
        "summary": f"주요 전송이 약 {terms.human_rate(ev.get('throughput_bps', 0))}에서 일정하게 막혀 있고, 응답 시간이 평소보다 {ev.get('rtt_inflation_ms')}ms 늘었어요. "
                   "회선 속도 제한(통신사·공유기 QoS)일 수 있지만, 원래 그 속도의 회선이거나 상대 서버가 느린 경우와 패킷만으로는 구분하기 어려워 '의심'으로 알려드려요.",
        "technical": f"flow throughput {ev.get('throughput_bps')} B/s cv={ev.get('cv')} over {ev.get('active_seconds')}s, RTT {ev.get('median_rtt_ms')}ms vs base {ev.get('baseline_rtt_ms')}ms",
        "analysis": {"what": "처리량이 일정 값에서 더 오르지 않고, 대기열이 쌓여 지연이 늘었어요.", "who": _full(who_src, a.get("src")), "protocol": "TCP",
                     "why": f"변동계수 {ev.get('cv')} (기준 {a['threshold']:g} 이하), RTT +{ev.get('rtt_inflation_ms')}ms", "impact": "다운로드·영상 화질이 제한돼요."},
        "false_positive": "원래 회선 속도가 그만큼이거나, 상대 서버가 속도를 제한하는 경우에도 똑같이 보여요. 다른 서버로 속도 측정을 해 비교해 보세요.",
        "recommendations": [_rec("connectivity_check", "연결 상태 점검", "지연·손실을 함께 측정해요."),
                            _rec("find_process", "대역폭을 쓰는 프로그램 찾기", "다른 전송이 대역폭을 차지하고 있을 수 있어요.")],
    }


def _size(a, ev, ctx, who_src, who_dst, local):
    k = ev.get("kind", "ICMP")
    return {
        "title": f"평소보다 큰 {k} 패킷이 반복돼요 (의심)",
        "summary": f"{k} 패킷은 보통 수십~수백 바이트인데, {ev.get('min_bytes')}바이트 이상인 패킷이 {a.get('measured')}개 보였어요. "
                   + ("핑 터널링(데이터 숨겨 보내기)이나 대형 핑 공격일 수 있지만, 큰 패킷으로 경로 MTU를 재는 정상 도구도 있어요." if k == "ICMP"
                      else "DNS 터널링이나 증폭 공격 응답일 수 있지만, DNSSEC·대형 TXT 레코드 응답처럼 정상적인 경우도 있어요."),
        "technical": f"{k} payload>={ev.get('min_bytes')}B count={ev.get('count')} in {ev.get('window_sec')}s",
        "analysis": {"what": f"{k} 패킷 크기 분포가 평소와 달라요.", "who": "여러 장치(프로토콜 기준 집계)", "protocol": k,
                     "why": f"{ev.get('window_sec')}초 동안 대형 {k} 패킷 {ev.get('count')}개 (기준 {a['threshold']}개)", "impact": "데이터 유출 통로나 회선 낭비일 수 있어요. 대부분은 영향이 없어요."},
        "false_positive": "MTU 측정 도구, DNSSEC 사용, 대형 TXT 레코드 조회는 정상이에요. 반복되지 않으면 무시해도 돼요.",
        "recommendations": [_rec("find_process", "관련 프로그램 찾기", "내 컴퓨터가 보낸 것이라면 어떤 프로그램인지 찾아요.")],
    }


def _proto_shift(a, ev, ctx, who_src, who_dst, local):
    p = ev.get("proto")
    return {
        "title": f"{p} 통신 비율이 평소보다 크게 늘었어요",
        "summary": f"평소 {p} 비율은 약 {round((ev.get('baseline_share') or 0) * 100)}%였는데 지금은 {round((ev.get('share') or 0) * 100)}%예요 "
                   f"(최근 {ev.get('window_sec')}초, 패킷 {ev.get('packets')}개). 영상통화·게임·스트리밍이 시작되면 자연스럽게 UDP가 늘어나므로 참고 정보예요.",
        "technical": f"{p} share {ev.get('share')} vs baseline {ev.get('baseline_share')} (learned {ev.get('learned_sec')}s), n={ev.get('packets')}",
        "analysis": {"what": "프로토콜 구성이 평소 기준선과 달라졌어요.", "who": "전체 네트워크", "protocol": p,
                     "why": f"비율 {ev.get('share')} (기준 {a['threshold']})", "impact": "그 자체로는 문제가 아니에요. 다른 징후와 함께 보면 원인 파악에 도움이 돼요."},
        "false_positive": "영상통화(UDP), 핑 테스트(ICMP), 새 앱 실행 등 정상적인 사용 변화에서도 나타나요.",
        "recommendations": [_rec("find_process", "관련 프로그램 찾기", "늘어난 통신을 어떤 프로그램이 하는지 찾아요.")],
    }


def _nx(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": "존재하지 않는 도메인 조회가 급증했어요 (의심)",
        "summary": f"{ev.get('window_sec')}초 동안 '그런 도메인이 없다'(NXDOMAIN)는 DNS 응답이 {ev.get('count')}건, 서로 다른 도메인 {ev.get('distinct_names')}개에서 나왔어요. "
                   "악성코드가 무작위 도메인을 생성해 서버를 찾는 패턴과 비슷하지만, 잘못된 검색 도메인 설정이나 광고 차단기도 비슷하게 보여요.",
        "technical": f"NXDOMAIN {ev.get('count')} over {ev.get('distinct_names')} names; samples={ev.get('samples')}",
        "analysis": {"what": "DNS 서버가 '없는 도메인'이라고 답한 질의가 많아요.", "who": "내 컴퓨터의 DNS 질의", "protocol": "DNS (UDP 53)",
                     "why": f"NXDOMAIN {ev.get('count')}건 (기준 {a['threshold']}건), 도메인 {ev.get('distinct_names')}개", "impact": "접속 실패가 반복되고, 드물게 악성코드 활동의 흔적일 수 있어요."},
        "false_positive": "검색 도메인(search domain) 설정, 광고 차단 DNS, 오타가 많은 브라우징에서도 나와요. 예시 도메인 목록을 확인해 보세요.",
        "recommendations": [_rec("dns_test", "DNS 테스트", "정상 도메인 조회가 되는지 확인해요."),
                            _rec("find_process", "질의한 프로그램 찾기", "무작위 도메인을 만드는 프로그램이 있는지 봐요.")],
    }


_EXPLAINERS.update({"packet_size_anomaly": _size, "proto_ratio_shift": _proto_shift, "dns_nxdomain_surge": _nx})
_EXPLAINERS.update({"arp_spoof": _arp, "ip_spoof_suspect": _ip_spoof, "dns_spoof_suspect": _dns_spoof, "latency_rise": _lat,
                    "jitter_high": _jit, "tcp_loss": _loss2, "connection_failure": _connfail, "bandwidth_limit_suspect": _bw})


def _csum(a, ev, ctx, who_src, who_dst, local):
    layers = ", ".join(f"{k} {v}건" for k, v in (ev.get("layers") or {}).items())
    return {
        "title": f"{who_src}에서 온 패킷의 체크섬이 맞지 않아요 (손상·변조 의심)",
        "summary": f"최근 {ev.get('window_sec')}초 동안 {who_src}에서 받은 패킷 {ev.get('checked')}개 중 {ev.get('bad')}개({round((ev.get('ratio') or 0) * 100)}%)의 "
                   f"체크섬이 내용과 맞지 않았어요. 전송 중 비트가 바뀌었거나(손상), 누군가 내용을 고치고 체크섬을 다시 계산하지 않았다는 뜻이에요. "
                   "일반 UDP 소켓은 운영체제가 이런 패킷을 조용히 버리므로 프로그램은 알 수 없어요.",
        "technical": f"bad checksum {ev.get('bad')}/{ev.get('checked')} ({layers}) from {a.get('src')}",
        "analysis": {"what": "수신 패킷의 IP·TCP·UDP·ICMP 체크섬 불일치", "who": who_src, "protocol": layers or "-",
                     "why": f"틀린 패킷 {ev.get('bad')}개 (기준 {a['threshold']}개 이상, 비율 {round((ev.get('ratio') or 0) * 100)}%)",
                     "impact": "운영체제가 버리므로 재전송·속도 저하가 생기고, 의도적인 변조라면 통신 방해 시도일 수 있어요."},
        "false_positive": "가상 머신·도커 브리지, 일부 USB 랜카드·드라이버는 체크섬을 나중에 계산해 캡처에서 틀려 보일 수 있어요. 손상된 케이블·무선 간섭도 원인이에요.",
        "recommendations": _ip_recs(a.get("src"), ctx, allow_block=False) + [
            _rec("connectivity_check", "연결 상태 점검", "손실·지연이 함께 늘었는지 확인해 물리적 손상인지 가려요.")],
    }


def _inject(a, ev, ctx, who_src, who_dst, local):
    kinds = ev.get("indicators") or {}
    names = {"rst_ttl": "평소와 다른 TTL의 연결 끊기(RST)", "rst_seq": "순서 번호가 크게 벗어난 RST",
             "data_ttl": "평소와 다른 TTL의 데이터", "data_after_rst": "RST 뒤에도 이어진 데이터"}
    txt = ", ".join(f"{names.get(k, k)} {v}건" for k, v in kinds.items())
    return {
        "title": "누군가 연결에 가짜 패킷을 끼워 넣고 있을 수 있어요 (TCP 주입 의심)",
        "summary": f"최근 {ev.get('window_sec')}초 동안 {ev.get('distinct_flows')}개 연결에서 {txt}이(가) 보였어요. "
                   "같은 서버에서 온 패킷이라면 거쳐 온 거리(TTL)가 거의 같아야 하는데, 다르면 중간 장비가 서버인 척 끼워 넣은 패킷일 수 있어요. "
                   "연결을 강제로 끊거나(RST 주입) 내용을 바꿔치기하는 공격·검열 장비가 이런 흔적을 남겨요.",
        "technical": "; ".join(ev.get("examples") or []),
        "analysis": {"what": "같은 연결 안에서 서로 맞지 않는 TTL·순서 번호", "who": ", ".join(ev.get("flows") or [])[:200] or "-", "protocol": "TCP",
                     "why": f"주입 징후 {a.get('measured')}건 (기준 {a['threshold']}건)", "impact": "웹·앱 연결이 갑자기 끊기거나, 받은 내용이 위조됐을 수 있어요."},
        "false_positive": "경로가 바뀌는 순간(로드밸런서·모바일 망 전환)이나 방화벽이 대신 보낸 정상 RST도 TTL이 다를 수 있어요. 반복될 때만 의미가 있어요.",
        "recommendations": [_rec("connectivity_check", "연결 상태 점검", "끊김이 특정 사이트에만 생기는지 확인해요."),
                            _rec("dns_test", "DNS 점검", "다른 DNS로도 같은 증상인지 확인해요.")],
    }


def _replay(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": f"이미 받은 UDP 패킷이 다시 도착하고 있어요 ({ev.get('protocol')} 재전송 의심)",
        "summary": f"{ev.get('flow')} 흐름에서 이미 받은 순서 번호가 {ev.get('duplicates')}번 다시 왔어요 (예: {', '.join(str(x) for x in (ev.get('sample_seq') or [])[:5])}). "
                   "UDP는 중복을 막아 주지 않으므로, 녹음해 둔 패킷을 다시 보내는 재전송(리플레이) 공격이면 받은 프로그램이 같은 명령·음성을 또 처리할 수 있어요.",
        "technical": f"{ev.get('protocol')} duplicate seq x{ev.get('duplicates')} flow={ev.get('flow')}",
        "analysis": {"what": "같은 순서 번호의 UDP 패킷 반복", "who": ev.get("flow") or "-", "protocol": ev.get("protocol") or "UDP",
                     "why": f"중복 {ev.get('duplicates')}건 (기준 {a['threshold']}건)", "impact": "같은 요청이 두 번 처리되거나 통화 품질이 떨어질 수 있어요."},
        "false_positive": "네트워크 장비의 중복 전송이나 FEC(오류 정정용 중복 전송)를 쓰는 앱도 같은 번호를 다시 보낼 수 있어요.",
        "recommendations": _ip_recs(a.get("src"), ctx),
    }


_EXPLAINERS.update({"checksum_error": _csum, "tcp_injection": _inject, "udp_replay": _replay})


def _cs_common(a, ev):
    origin = (f"CrowdSec의 {ev.get('crowdsec')} 시나리오와 같은 조건(leaky bucket)으로 판정했어요. " if ev.get("crowdsec") else
              "CrowdSec에는 없는 NetCare 확장 조건(URL 디코딩 후 비교·SQL 문법·로그인 반복)으로 판정했어요. ")
    return (origin
            + (f"일치한 패턴: {', '.join(ev.get('matches') or [])[:200]}. " if ev.get("matches") else ""))


def _web_attack(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": f"{who_src}이(가) 웹 서버에 {ev.get('scenario_label')}을(를) 하고 있어요",
        "summary": f"{who_src}이(가) {who_dst}의 웹 서버(포트 {a.get('port')})로 보낸 평문 HTTP 요청에서 공격 패턴이 보였어요. " + _cs_common(a, ev)
                   + "공격을 '시도'한 것은 확실하지만 성공했는지는 서버 응답·로그를 확인해야 해요.",
        "technical": f"{ev.get('crowdsec')} events={ev.get('events')} samples={ev.get('samples')}",
        "analysis": {"what": ev.get("scenario_label"), "who": _full(who_src, a['src']), "protocol": "HTTP (평문)",
                     "why": a.get("criterion"), "impact": "취약한 웹 애플리케이션이라면 정보 유출·서버 장악으로 이어질 수 있어요."},
        "false_positive": "보안 점검 도구를 직접 돌렸거나, 검색 로봇이 우연히 비슷한 경로를 요청한 경우일 수 있어요.",
        "recommendations": _ip_recs(a.get("src"), ctx),
    }


def _web_scan(a, ev, ctx, who_src, who_dst, local):
    return {
        "title": f"{who_src}이(가) 웹 서버를 훑고 있어요 ({ev.get('scenario_label')})",
        "summary": f"{who_src}이(가) {who_dst}의 웹 서버에 짧은 시간 동안 요청을 많이 보냈어요. " + _cs_common(a, ev)
                   + "취약점을 찾기 전 단계의 탐색인 경우가 많아요.",
        "technical": f"{ev.get('crowdsec')} events={ev.get('events')} samples={ev.get('samples')}",
        "analysis": {"what": ev.get("scenario_label"), "who": _full(who_src, a['src']), "protocol": "HTTP (평문)",
                     "why": a.get("criterion"), "impact": "직접적인 피해는 없지만 공격 대상 목록에 오를 수 있어요."},
        "false_positive": "검색 엔진 로봇, 링크 검사기, 내가 쓰는 개발 도구도 비슷한 패턴을 만들어요.",
        "recommendations": _ip_recs(a.get("src"), ctx),
    }


def _bruteforce(a, ev, ctx, who_src, who_dst, local):
    ssh = ev.get("scenario") == "ssh_bf"
    return {
        "title": f"{who_src}이(가) {'SSH' if ssh else ('웹' if ev.get('scenario') == 'ext_http_login_bf' else 'FTP')} 로그인을 반복해서 시도하고 있어요" + (" (의심)" if ssh else ""),
        "summary": (f"{who_src}이(가) {who_dst}의 SSH 서버에 짧은 간격으로 연결을 계속 시도했어요. SSH는 암호화되어 로그인 실패 여부를 패킷으로 볼 수 없어, "
                    "연결 시도 수로 판단했어요. " if ssh else
                    (f"{who_src}이(가) 같은 로그인 주소로 POST 요청을 짧은 간격으로 계속 보냈어요. " if ev.get("scenario") == "ext_http_login_bf" else
                     f"{who_src}의 FTP 로그인이 짧은 간격으로 계속 실패했어요(서버 응답 530). ")) + _cs_common(a, ev),
        "technical": f"{ev.get('crowdsec') or ev.get('scenario')} events={ev.get('events')}",
        "analysis": {"what": ev.get("scenario_label"), "who": _full(who_src, a['src']), "protocol": "SSH" if ssh else ("HTTP" if ev.get("scenario") == "ext_http_login_bf" else "FTP"),
                     "why": a.get("criterion"), "impact": "비밀번호가 약하면 계정을 빼앗길 수 있어요."},
        "false_positive": "자동 배포·백업 스크립트가 짧은 간격으로 접속하는 경우도 있어요." if ssh else "비밀번호를 잊은 사용자가 여러 번 시도한 경우일 수 있어요.",
        "recommendations": _ip_recs(a.get("src"), ctx),
    }


_EXPLAINERS.update({"web_attack": _web_attack, "web_scan": _web_scan, "auth_bruteforce": _bruteforce})
