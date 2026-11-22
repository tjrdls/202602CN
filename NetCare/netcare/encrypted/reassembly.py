"""TCP 순서 번호(SEQ) 기반 재조립 — TLS ClientHello/ServerHello 가 여러 세그먼트로 나뉜 경우.

도착 순서대로 이어 붙이지 않는다. 각 세그먼트를 '기준 순서 번호로부터의 위치(offset)'에 놓고,
처음부터 빈틈없이 이어지는 구간만 읽는다.

처리하는 상황
- 순서 뒤바뀜: 뒤 세그먼트가 먼저 와도 위치에 맞게 놓는다 (reordered)
- 중복·재전송: 같은 위치의 같은 데이터는 한 번만 쓴다 (duplicates)
- 겹침: 일부만 겹치면 겹친 부분을 잘라낸다. 겹친 부분의 내용이 다르면 따로 센다 (overlap_conflicts — 주입·우회 시도 신호)
- 누락: 빈틈이 메워지지 않은 채 시간이 지나거나 연결이 끝나면 '분석 실패(누락)'로 기록한다

메모리: 흐름당 최대 MAX_STREAM_BYTES, 동시에 추적하는 흐름 MAX_STREAMS 개 (넘으면 가장 오래된 것부터 버림).
ClientHello·ServerHello 를 다 읽으면 그 흐름의 버퍼는 바로 비운다.
"""
from __future__ import annotations

from collections import OrderedDict

from netcare.encrypted.tls_hello import parse_client_hello, parse_server_hello

SEQ_MOD = 1 << 32
MAX_STREAM_BYTES = 32 * 1024
MAX_STREAMS = 4096
TIMEOUT_SEC = 5.0
TLS_PORTS = {443, 853, 8443, 993, 995, 465, 636, 989, 990, 5223, 5061}


def _off(seq: int, base: int) -> int:
    d = (seq - base) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_MOD // 2 else d


def looks_like_tls_handshake(b: bytes) -> bool:
    return len(b) >= 6 and b[0] == 0x16 and b[1] == 0x03 and b[2] <= 0x04


class _Stream:
    __slots__ = ("base", "segs", "first_ts", "last_ts", "nseg", "dups", "reordered", "conflicts", "max_end", "want", "pending", "tls_seen", "from_syn")

    def __init__(self, want: int, ts: float):
        self.base: int | None = None
        self.segs: dict[int, bytes] = {}        # offset → bytes (서로 겹치지 않게 저장)
        self.first_ts = self.last_ts = ts
        self.nseg = self.dups = self.reordered = self.conflicts = 0
        self.max_end = 0
        self.want = want                       # 1 = ClientHello, 2 = ServerHello
        self.pending: list = []                # SYN 없이 시작해 기준점을 아직 못 정한 세그먼트
        self.tls_seen = False                  # 흐름 맨 앞에서 TLS 핸드셰이크 머리를 봤는가 (아니면 실패로 세지 않음)
        self.from_syn = False                  # 연결 시작(SYN)을 봤는가


class TcpReassembler:
    def __init__(self, max_streams: int = MAX_STREAMS):
        self.streams: OrderedDict[tuple, _Stream] = OrderedDict()
        self.max_streams = max_streams
        # SYN 을 못 본 흐름에서 TLS 머리보다 뒤 조각이 먼저 온 경우를 위해, 추적하지 않는 흐름의 최근 조각을 잠깐 보관
        self.orphans: OrderedDict[tuple, list] = OrderedDict()
        self.stats = {"started": 0, "complete": 0, "complete_multi": 0, "failed": 0, "evicted": 0, "reordered": 0,
                      "duplicates": 0, "conflicts": 0}
        self.fail_reasons: dict[str, int] = {}

    # ───────────── 입력 ─────────────
    def syn(self, key: tuple, seq: int, ts: float, want: int):
        """SYN(또는 SYN-ACK): 데이터는 seq+1 부터 시작한다."""
        st = self._get(key, ts, want, create=True)
        st.base = (seq + 1) % SEQ_MOD
        st.from_syn = True

    def track(self, key: tuple) -> bool:
        return key in self.streams

    def feed(self, key: tuple, seq: int, data: bytes, ts: float, want: int = 1, fin: bool = False) -> dict | None:
        """세그먼트 하나. 목표 메시지가 완성되거나 실패하면 결과를 돌려준다 (그 외 None)."""
        st = self.streams.get(key)
        if st is None:
            if not data:
                return None
            if not looks_like_tls_handshake(data):
                # TLS 핸드셰이크로 시작하지 않는 조각: 흐름당 4개, 2초까지만 보관 (뒤 조각이 먼저 온 경우 대비)
                lst = self.orphans.setdefault(key, [])
                lst[:] = [x for x in lst if ts - x[2] <= 2.0][-3:] + [(seq, data, ts)]
                self.orphans.move_to_end(key)
                while len(self.orphans) > 2048:
                    self.orphans.popitem(last=False)
                return None
            st = self._get(key, ts, want, create=True)
            st.pending = [(s_, d_) for s_, d_, t_ in self.orphans.pop(key, []) if ts - t_ <= 2.0]
        st.last_ts = ts
        if data:
            if st.base is None:
                # SYN 을 못 본 연결: TLS 레코드 머리로 시작하는 세그먼트를 기준점으로 삼는다
                st.pending.append((seq, data))
                heads = [s for s, d in st.pending if looks_like_tls_handshake(d)]
                if not heads:
                    return None
                st.base = min(heads, key=lambda s: _off(s, heads[0]))
                for s, d in st.pending:
                    self._place(st, s, d)
                st.pending = []
            else:
                if not st.segs and _off(seq, st.base) == 0 and not looks_like_tls_handshake(data):
                    del self.streams[key]               # SYN 으로 시작했지만 TLS 가 아닌 연결 (HTTP 등) → 조용히 추적 중단
                    return None
                self._place(st, seq, data)
            if 0 in st.segs and looks_like_tls_handshake(st.segs[0]):
                st.tls_seen = True
            res = self._try_parse(key, st)
            if res is not None:
                return res
            if st.max_end > MAX_STREAM_BYTES:
                return self._fail(key, st, "too_large", f"{MAX_STREAM_BYTES // 1024}KB 안에 메시지가 끝나지 않음")
        if fin:
            return self._fail(key, st, "closed", "메시지가 끝나기 전에 연결이 끝남 (누락된 세그먼트)" if st.segs else "데이터 없이 연결이 끝남")
        return None

    def expire(self, now: float) -> list[dict]:
        """오래 메워지지 않은 빈틈 → 실패로 정리."""
        out = []
        for key in [k for k, s in self.streams.items() if now - s.last_ts > TIMEOUT_SEC]:
            st = self.streams[key]
            res = self._fail(key, st, "gap_timeout", f"{TIMEOUT_SEC:g}초 동안 빠진 세그먼트가 오지 않음") if (st.segs or st.pending) else None
            if res:
                out.append(res)
            self.streams.pop(key, None)
        return out

    # ───────────── 내부 ─────────────
    def _get(self, key, ts, want, create=False) -> _Stream:
        st = self.streams.get(key)
        if st is None and create:
            if len(self.streams) >= self.max_streams:
                self.streams.popitem(last=False)
                self.stats["evicted"] += 1
            st = self.streams[key] = _Stream(want, ts)
            self.stats["started"] += 1
        return st

    def _place(self, st: _Stream, seq: int, data: bytes):
        off = _off(seq, st.base)
        end = off + len(data)
        if end <= 0 or off > MAX_STREAM_BYTES * 2:
            return                              # 기준점 이전(이미 지난 데이터) 또는 터무니없이 먼 위치
        if off < 0:
            data, off = data[-off:], 0
        st.nseg += 1
        if off < st.max_end and off not in st.segs and end > off:
            # 이미 받은 위치보다 앞쪽 데이터가 늦게 도착
            if not any(o <= off < o + len(d) for o, d in st.segs.items()):
                st.reordered += 1
        # 겹치는 부분 처리: 먼저 도착한 데이터를 기준으로 남는 부분만 저장
        pieces = [(off, data)]
        for o, d in sorted(st.segs.items()):
            nxt = []
            for po, pd in pieces:
                pe = po + len(pd)
                oe = o + len(d)
                if pe <= o or po >= oe:
                    nxt.append((po, pd))
                    continue
                lo, hi = max(po, o), min(pe, oe)
                if pd[lo - po:hi - po] != d[lo - o:hi - o]:
                    st.conflicts += 1
                else:
                    st.dups += 1 if (lo == po and hi == pe) else 0
                if po < lo:
                    nxt.append((po, pd[:lo - po]))
                if pe > hi:
                    nxt.append((hi, pd[hi - po:]))
            pieces = nxt
        for po, pd in pieces:
            if pd:
                st.segs[po] = pd
        st.max_end = max(st.max_end, end)

    def _contiguous(self, st: _Stream) -> bytes:
        out, pos = bytearray(), 0
        for o in sorted(st.segs):
            if o > pos:
                break
            d = st.segs[o]
            if o + len(d) > pos:
                out += d[pos - o:]
                pos = o + len(d)
        return bytes(out)

    def _try_parse(self, key, st: _Stream) -> dict | None:
        buf = self._contiguous(st)
        hs = bytearray()
        p = 0
        while p + 5 <= len(buf):
            ctype, rlen = buf[p], int.from_bytes(buf[p + 3:p + 5], "big")
            if ctype != 22:
                break                            # 핸드셰이크 레코드가 끝남
            hs += buf[p + 5:p + 5 + rlen]
            if p + 5 + rlen > len(buf):
                break                            # 레코드가 아직 다 오지 않음
            p += 5 + rlen
            if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
                break
        if len(hs) < 4:
            return None
        need = 4 + int.from_bytes(hs[1:4], "big")
        if hs[0] != st.want:
            if not st.from_syn:
                # 캡처 전에 이미 열린 연결 중간의 핸드셰이크 레코드(재협상 등): 새 연결의 ClientHello 가 아니므로 대상 아님
                self.streams.pop(key, None)
                return None
            return self._fail(key, st, "unexpected", "첫 핸드셰이크 메시지가 " + ("ClientHello" if st.want == 1 else "ServerHello") + "가 아님")
        if len(hs) < need:
            return None
        hello = parse_client_hello(bytes(hs[:need])) if st.want == 1 else parse_server_hello(bytes(hs[:need]))
        res = {"status": "complete", "segments": st.nseg, "bytes": need, "reordered": st.reordered, "duplicates": st.dups,
               "conflicts": st.conflicts, "multi_segment": len([o for o in st.segs if o < need]) > 1, "hello": hello}
        self.stats["complete"] += 1
        self.stats["complete_multi"] += 1 if res["multi_segment"] else 0
        self._count(st)
        del self.streams[key]
        return res

    def _count(self, st):
        self.stats["reordered"] += st.reordered
        self.stats["duplicates"] += st.dups
        self.stats["conflicts"] += st.conflicts

    def _fail(self, key, st, code, reason) -> dict | None:
        if not st.tls_seen and not st.pending:
            # TLS 라는 증거가 없는 흐름(데이터 없이 끝남, TLS 가 아닌 포트)은 재조립 대상이 아니었던 것으로 본다.
            # 단, TLS 포트에서 데이터가 왔는데 첫 조각이 빠진 경우는 '첫 조각 누락' 실패로 기록한다.
            if st.segs and (key[3] in TLS_PORTS or key[1] in TLS_PORTS):
                reason = "첫 조각(TLS 머리)이 오지 않음 · " + reason
            else:
                self.streams.pop(key, None)
                return None
        self.stats["failed"] += 1
        self.fail_reasons[code] = self.fail_reasons.get(code, 0) + 1
        self._count(st)
        self.streams.pop(key, None)
        return {"status": "failed", "code": code, "reason": reason, "segments": st.nseg, "bytes_seen": st.max_end,
                "reordered": st.reordered, "duplicates": st.dups, "conflicts": st.conflicts}
