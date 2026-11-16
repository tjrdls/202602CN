"""초보자 친화형 용어 변환 사전.

전문 용어(포트, 프로토콜, TCP 플래그, 헤더 필드)를 일반 사용자가 이해할 수 있는
한국어 표현으로 바꾼다. 전문가 모드에서는 원래 이름도 함께 보여 준다.
"""
from __future__ import annotations

import ipaddress

# (프로토콜, 포트) → (짧은 이름, 쉬운 설명)
# 프로토콜이 None 이면 TCP/UDP 공통
SERVICES: dict[tuple[str | None, int], tuple[str, str]] = {
    ("TCP", 20): ("FTP 데이터", "파일 전송(FTP) 데이터"),
    ("TCP", 21): ("FTP", "파일 전송(FTP) 제어"),
    ("TCP", 22): ("SSH", "원격 접속(SSH, 암호화)"),
    ("TCP", 23): ("Telnet", "원격 접속(Telnet, 암호화 안 됨)"),
    ("TCP", 25): ("SMTP", "메일 보내기"),
    (None, 53): ("DNS", "도메인 주소 조회(DNS)"),
    ("UDP", 67): ("DHCP", "IP 주소 자동 할당(DHCP)"),
    ("UDP", 68): ("DHCP", "IP 주소 자동 할당(DHCP)"),
    ("TCP", 80): ("HTTP", "웹 통신(HTTP, 암호화 안 됨)"),
    ("TCP", 110): ("POP3", "메일 받기(POP3)"),
    ("UDP", 123): ("NTP", "시간 동기화(NTP)"),
    ("UDP", 137): ("NetBIOS", "윈도우 파일 공유 이름 확인"),
    ("UDP", 138): ("NetBIOS", "윈도우 파일 공유 알림"),
    ("TCP", 139): ("NetBIOS", "윈도우 파일 공유"),
    ("TCP", 143): ("IMAP", "메일 받기(IMAP)"),
    ("UDP", 161): ("SNMP", "네트워크 장비 관리(SNMP)"),
    ("TCP", 443): ("HTTPS", "HTTPS 웹 통신(암호화)"),
    ("UDP", 443): ("QUIC", "빠른 HTTPS 웹 통신(QUIC, 암호화)"),
    ("TCP", 445): ("SMB", "파일 공유(SMB)"),
    ("TCP", 465): ("SMTPS", "메일 보내기(암호화)"),
    ("TCP", 587): ("SMTP", "메일 보내기"),
    ("TCP", 853): ("DoT", "암호화된 DNS 조회"),
    ("TCP", 993): ("IMAPS", "메일 받기(암호화)"),
    ("TCP", 995): ("POP3S", "메일 받기(암호화)"),
    ("UDP", 1900): ("SSDP", "공유기·스마트기기 자동 찾기(SSDP)"),
    ("TCP", 3306): ("MySQL", "데이터베이스(MySQL)"),
    ("TCP", 3389): ("RDP", "윈도우 원격 데스크톱"),
    ("UDP", 3478): ("STUN", "화상통화·게임 연결 설정(STUN)"),
    ("TCP", 5223): ("APNs", "애플 푸시 알림"),
    ("TCP", 5228): ("FCM", "구글 푸시 알림"),
    ("UDP", 5353): ("mDNS", "같은 네트워크 장치 자동 찾기(mDNS)"),
    ("UDP", 5355): ("LLMNR", "같은 네트워크 이름 확인(LLMNR)"),
    ("TCP", 5432): ("PostgreSQL", "데이터베이스(PostgreSQL)"),
    ("TCP", 8080): ("HTTP-ALT", "웹 통신(대체 포트)"),
    ("TCP", 8443): ("HTTPS-ALT", "HTTPS 웹 통신(대체 포트)"),
}

# 흔히 대량 트래픽이 정상적으로 발생하는 서비스 포트 (오탐 완화용)
COMMON_BULK_PORTS = {80, 443, 53, 8080, 8443, 5353, 1900}


def service_for(proto: str, sport: int | None, dport: int | None) -> tuple[str, str, int | None]:
    """패킷의 서비스(짧은 이름, 설명, 서비스 포트)를 추정한다.

    잘 알려진 포트가 있는 쪽을 서비스 포트로 본다. 둘 다 모르면 작은 번호를 쓴다.
    """
    if proto not in ("TCP", "UDP") or sport is None or dport is None:
        return ("", "", None)
    for p in (dport, sport):
        hit = SERVICES.get((proto, p)) or SERVICES.get((None, p))
        if hit:
            return (hit[0], hit[1], p)
    port = min(sport, dport)
    if port < 1024:
        return (f"{proto}/{port}", f"잘 알려진 서비스 포트 {port}번", port)
    return (f"{proto}/{port}", f"{port}번 포트 통신", port)


PROTOCOLS = {
    "TCP": "연결을 맺고 순서대로 안전하게 보내는 통신(TCP)",
    "UDP": "연결 없이 빠르게 보내는 통신(UDP)",
    "ICMP": "네트워크 연결 상태 확인에 사용되는 통신(ICMP)",
    "ICMPv6": "IPv6 네트워크 연결 상태 확인 통신(ICMPv6)",
    "ARP": "같은 네트워크에서 장치 주소를 묻는 통신(ARP)",
    "IGMP": "그룹 방송(멀티캐스트) 참여 알림(IGMP)",
    "OTHER": "기타 통신",
}

TCP_FLAG_FRIENDLY = {
    "S": "새로운 연결 요청",
    "SA": "연결 요청 수락",
    "A": "받았다는 확인",
    "PA": "데이터 전송",
    "FA": "연결 종료 요청",
    "F": "연결 종료 요청",
    "R": "연결 강제 종료",
    "RA": "연결 거부/강제 종료",
}

TCP_FLAG_NAMES = {
    "F": "FIN(종료)", "S": "SYN(연결 요청)", "R": "RST(강제 종료)", "P": "PSH(즉시 전달)",
    "A": "ACK(확인)", "U": "URG(긴급)", "E": "ECE(혼잡 알림)", "C": "CWR(혼잡 감소)",
}

ICMP_TYPES = {
    0: "응답(ping 응답)", 3: "목적지에 도달할 수 없음", 5: "경로 변경 안내",
    8: "응답 요청(ping)", 11: "시간 초과(경로 너무 김)",
}

DNS_RCODES = {0: "성공", 1: "형식 오류", 2: "서버 오류(SERVFAIL)", 3: "존재하지 않는 도메인(NXDOMAIN)",
              4: "지원 안 함", 5: "거부됨"}

# 상세 화면 계층/필드 한국어 이름
LAYER_NAMES = {
    "Ethernet": "이더넷 (같은 네트워크 안에서의 전달)",
    "Loopback": "루프백 (내 컴퓨터 내부 통신)",
    "IP": "IPv4 (인터넷 주소 체계)",
    "IPv6": "IPv6 (차세대 인터넷 주소 체계)",
    "TCP": "TCP (신뢰성 있는 연결형 전송)",
    "UDP": "UDP (빠른 비연결형 전송)",
    "ICMP": "ICMP (연결 상태 확인)",
    "DNS": "DNS (도메인 주소 조회)",
    "ARP": "ARP (장치 주소 확인)",
    "Raw": "데이터 (응용 계층 내용)",
    "Padding": "채움 바이트",
}

FIELD_LABELS = {
    ("Ethernet", "dst"): ("받는 장치 MAC 주소", "같은 네트워크 안에서 이 데이터를 받을 장치의 하드웨어 주소"),
    ("Ethernet", "src"): ("보내는 장치 MAC 주소", "이 데이터를 보낸 장치의 하드웨어 주소"),
    ("Ethernet", "type"): ("EtherType", "안에 담긴 데이터 종류 (0x0800=IPv4, 0x86dd=IPv6, 0x0806=ARP)"),
    ("IP", "version"): ("버전", "IP 주소 체계의 버전"),
    ("IP", "ihl"): ("헤더 길이", "IP 헤더 길이 (4바이트 단위)"),
    ("IP", "tos"): ("서비스 유형", "우선순위/혼잡 표시"),
    ("IP", "len"): ("전체 길이", "IP 패킷 전체 크기(바이트)"),
    ("IP", "id"): ("식별자", "조각난 패킷을 다시 합칠 때 쓰는 번호"),
    ("IP", "flags"): ("플래그", "조각화 관련 표시 (DF=조각내지 말 것)"),
    ("IP", "frag"): ("조각 위치", "조각난 패킷의 위치"),
    ("IP", "ttl"): ("TTL (생존 시간)", "라우터를 하나 지날 때마다 1씩 줄고 0이 되면 버려짐"),
    ("IP", "proto"): ("상위 프로토콜", "안에 담긴 전송 방식 (6=TCP, 17=UDP, 1=ICMP)"),
    ("IP", "chksum"): ("체크섬", "헤더 오류 검사 값"),
    ("IP", "src"): ("보내는 장치 (Source IP)", "데이터를 보내는 장치의 IP 주소"),
    ("IP", "dst"): ("받는 장치 (Destination IP)", "데이터를 받는 장치의 IP 주소"),
    ("IPv6", "plen"): ("데이터 길이", "IPv6 헤더 뒤 데이터 크기"),
    ("IPv6", "nh"): ("다음 헤더", "안에 담긴 전송 방식"),
    ("IPv6", "hlim"): ("Hop Limit (생존 시간)", "IPv4의 TTL과 같은 역할"),
    ("IPv6", "src"): ("보내는 장치 (Source IP)", "데이터를 보내는 장치의 IPv6 주소"),
    ("IPv6", "dst"): ("받는 장치 (Destination IP)", "데이터를 받는 장치의 IPv6 주소"),
    ("TCP", "sport"): ("보내는 쪽 포트", "보내는 프로그램을 구분하는 번호"),
    ("TCP", "dport"): ("받는 쪽 포트", "받는 프로그램(서비스)을 구분하는 번호"),
    ("TCP", "seq"): ("순서 번호 (Sequence)", "보내는 데이터의 순서를 나타내는 번호"),
    ("TCP", "ack"): ("확인 번호 (Acknowledgment)", "여기까지 잘 받았다는 번호"),
    ("TCP", "dataofs"): ("헤더 길이", "TCP 헤더 길이 (4바이트 단위)"),
    ("TCP", "flags"): ("TCP 플래그", "연결 요청(SYN)/확인(ACK)/종료(FIN)/강제종료(RST) 등"),
    ("TCP", "window"): ("윈도우 크기", "한 번에 더 받을 수 있는 데이터 양 (흐름 제어)"),
    ("TCP", "chksum"): ("체크섬", "오류 검사 값"),
    ("TCP", "urgptr"): ("긴급 포인터", "긴급 데이터 위치"),
    ("TCP", "options"): ("옵션", "MSS, 타임스탬프 등 추가 협상 정보"),
    ("UDP", "sport"): ("보내는 쪽 포트", "보내는 프로그램을 구분하는 번호"),
    ("UDP", "dport"): ("받는 쪽 포트", "받는 프로그램(서비스)을 구분하는 번호"),
    ("UDP", "len"): ("UDP 길이", "UDP 헤더+데이터 크기(바이트)"),
    ("UDP", "chksum"): ("체크섬", "오류 검사 값"),
    ("ICMP", "type"): ("종류", "8=ping 요청, 0=ping 응답, 3=도달 불가, 11=시간 초과"),
    ("ICMP", "code"): ("세부 코드", "종류별 세부 이유"),
    ("ICMP", "chksum"): ("체크섬", "오류 검사 값"),
    ("ICMP", "id"): ("식별자", "ping 요청과 응답을 짝짓는 번호"),
    ("ICMP", "seq"): ("순서 번호", "몇 번째 ping 인지"),
    ("IPv6", "version"): ("버전", "6"),
    ("IPv6", "tc"): ("트래픽 클래스", "우선순위 표시"),
    ("IPv6", "fl"): ("흐름 라벨", "같은 흐름의 패킷 묶음 표시"),
    ("DNS", "id"): ("질의 번호", "질문과 응답을 짝짓는 번호"),
    ("DNS", "qr"): ("질문/응답", "0=질문, 1=응답"),
    ("DNS", "rcode"): ("응답 코드", "0=성공, 2=서버 오류, 3=없는 도메인"),
    ("ARP", "hwtype"): ("하드웨어 종류", "1=이더넷"),
    ("ARP", "ptype"): ("프로토콜 종류", "찾으려는 주소 종류 (0x0800=IPv4)"),
    ("ARP", "hwlen"): ("하드웨어 주소 길이", "MAC 주소 길이(바이트)"),
    ("ARP", "plen"): ("프로토콜 주소 길이", "IP 주소 길이(바이트)"),
    ("ARP", "hwdst"): ("찾는 장치 MAC", "요청일 때는 아직 모르므로 00:00:00:00:00:00"),
    ("ARP", "op"): ("동작", "1=누구세요?(요청), 2=저예요(응답)"),
    ("ARP", "psrc"): ("보내는 장치 IP", ""),
    ("ARP", "pdst"): ("찾는 장치 IP", ""),
    ("ARP", "hwsrc"): ("보내는 장치 MAC", ""),
}


_LOCAL_NETS = [ipaddress.ip_network(n) for n in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def _is_local_net(a) -> bool:
    return any(a in n for n in _LOCAL_NETS if n.version == a.version)


def describe_ip(ip: str | None, local_ips: set[str] | None = None, names: dict | None = None) -> str:
    """IP 를 사람이 이해하기 쉬운 장치 설명으로 바꾼다."""
    if not ip:
        return "알 수 없는 장치"
    if local_ips and ip in local_ips:
        return "내 컴퓨터"
    name = names.get(ip) if names else None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.is_loopback:
        return "내 컴퓨터(내부)"
    if a.is_multicast:
        return "여러 장치에 동시 전달(멀티캐스트)"
    if a.version == 4 and (ip == "255.255.255.255" or ip.endswith(".255")):
        return "같은 네트워크 전체(브로드캐스트)"
    if _is_local_net(a):
        return f"같은 네트워크의 장치({ip})"
    if name:
        return f"{name}"
    return f"외부 인터넷({ip})"


def ip_scope(ip: str | None) -> str:
    """'local' (사설/링크로컬), 'public', 'special' 중 하나.

    주의: 파이썬의 is_private 는 문서용 예제 대역(203.0.113.0/24 등)도 사설로 보기 때문에
    RFC 1918 등 실제 사설망 대역 목록으로 직접 판정한다.
    """
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return "special"
    if a.is_loopback or a.is_multicast or a.is_unspecified:
        return "special"
    if _is_local_net(a):
        return "local"
    return "public"


def human_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_rate(bytes_per_sec: float) -> str:
    """바이트/초 → 비트 기반 속도 표기 (일반적인 인터넷 속도 단위)."""
    bits = float(bytes_per_sec or 0) * 8
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bits < 1000 or unit == "Gbps":
            return f"{bits:.0f} {unit}" if unit == "bps" else f"{bits:.1f} {unit}"
        bits /= 1000
    return f"{bits:.1f} Gbps"
