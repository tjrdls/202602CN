"""최신 암호화 통신 분석 (TLS 1.3·ECH·PQC·QUIC·암호화 DNS).

모든 분석은 '관찰 가능한 평문'만 읽는다. 암호화된 내용은 복호화하지 않으며(QUIC Initial 은 규격상 공개된
키로 보호되므로 예외), 볼 수 없는 정보는 추측하지 않고 '분석 제한'으로 표시한다.

- tls_hello   : ClientHello/ServerHello 완전 해석 (버전, ALPN, 지원 그룹, Key Share, ECH, PQC)
- reassembly  : TCP 순서 번호 기반 재조립 (ClientHello 가 여러 세그먼트로 나뉜 경우)
- quic        : QUIC Initial 키 도출·복호화, CRYPTO 프레임 재조립, HTTP/3 판정
- dns_class   : 일반 DNS / DoT / DoQ / DoH 분류 (확인·추정 구분)
- analyzer    : 위 모듈을 묶어 패킷 레코드에 결과를 붙이고 통계를 낸다
"""

# 분석 상태 (모든 결과에 붙는다)
CONFIRMED = "confirmed"     # 확인됨: 실제 패킷에서 추출
ESTIMATED = "estimated"     # 추정됨: 여러 지표로 가능성 판단
LIMITED = "limited"         # 분석 제한: 암호화(ECH 등)로 필요한 정보를 볼 수 없음
FAILED = "failed"           # 분석 실패: 누락·재조립 실패·미지원 등

STATUS_KO = {CONFIRMED: "확인됨", ESTIMATED: "추정됨", LIMITED: "분석 제한", FAILED: "분석 실패"}
