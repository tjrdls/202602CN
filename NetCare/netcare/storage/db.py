"""SQLite 저장소.

- WAL 모드: 처리 스레드가 쓰는 동안에도 웹 요청이 동시에 읽을 수 있다.
- 쓰기는 하나의 연결 + 잠금으로 직렬화, 읽기는 스레드별 연결을 사용한다.
- 패킷 테이블은 보존 한도(max_db_packets)를 넘으면 오래된 것부터 삭제한다.
  리포트용 분 단위 집계(traffic_minute)는 별도로 남아 장기 통계에 쓰인다.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL, ended_at REAL,
    source TEXT NOT NULL,            -- live | pcap | test
    iface TEXT, bpf_filter TEXT, note TEXT,
    packets INTEGER DEFAULT 0, dropped INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL, source TEXT NOT NULL,
    ts REAL NOT NULL, length INTEGER NOT NULL,
    src TEXT, dst TEXT, proto TEXT, sport INTEGER, dport INTEGER,
    flags TEXT, ttl INTEGER, direction TEXT,
    service TEXT, info TEXT, friendly TEXT,
    src_mac TEXT, dst_mac TEXT, first_layer TEXT, raw BLOB
);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id, id);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst);
CREATE INDEX IF NOT EXISTS idx_packets_sport ON packets(sport);
CREATE INDEX IF NOT EXISTS idx_packets_dport ON packets(dport);
CREATE TABLE IF NOT EXISTS traffic_minute (
    minute INTEGER NOT NULL, session_id INTEGER NOT NULL, source TEXT NOT NULL,
    packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
    up_bytes INTEGER DEFAULT 0, down_bytes INTEGER DEFAULT 0,
    tcp INTEGER DEFAULT 0, udp INTEGER DEFAULT 0, icmp INTEGER DEFAULT 0, other INTEGER DEFAULT 0,
    PRIMARY KEY (minute, session_id)
);
CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER, source TEXT,
    detected_at REAL NOT NULL, last_seen REAL NOT NULL,
    type TEXT NOT NULL, severity TEXT NOT NULL,
    src TEXT, dst TEXT, port INTEGER, protocol TEXT,
    criterion TEXT, threshold REAL, measured REAL, peak REAL,
    evidence TEXT, explanation TEXT,
    count INTEGER DEFAULT 1, status TEXT DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_anom_time ON anomalies(detected_at);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL, anomaly_id INTEGER,
    action TEXT NOT NULL, params TEXT, trigger TEXT DEFAULT 'user',
    status TEXT NOT NULL, simulated INTEGER DEFAULT 0,
    before_state TEXT, result TEXT, verification TEXT,
    rollback_info TEXT, rolled_back_at REAL, rollback_result TEXT, expires_at REAL
);
CREATE TABLE IF NOT EXISTS health_history (
    ts REAL NOT NULL, session_id INTEGER, source TEXT,
    score INTEGER, status TEXT, components TEXT
);
CREATE INDEX IF NOT EXISTS idx_health_ts ON health_history(ts);
CREATE TABLE IF NOT EXISTS ip_names (
    ip TEXT PRIMARY KEY, name TEXT, updated REAL
);
"""

PACKET_COLS = ("session_id", "source", "ts", "length", "src", "dst", "proto", "sport", "dport", "flags", "ttl",
               "direction", "service", "info", "friendly", "src_mac", "dst_mac", "first_layer", "raw")
LIST_COLS = "id, session_id, source, ts, length, src, dst, proto, sport, dport, flags, ttl, direction, service, info, friendly, src_mac, dst_mac"

JSON_FIELDS = {"evidence", "explanation", "params", "before_state", "result", "verification", "rollback_info",
               "rollback_result", "components"}


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in JSON_FIELDS & d.keys():
        if d[k]:
            try:
                d[k] = json.loads(d[k])
            except (TypeError, json.JSONDecodeError):
                pass
    return d


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._wlock = threading.RLock()
        self._w = self._connect()
        self._w.executescript(SCHEMA)
        self._w.commit()
        self._local = threading.local()
        self._inserts_since_prune = 0

    def _connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        return c

    def _r(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._connect()
            self._local.conn = c
        return c

    def query(self, sql: str, params: Iterable = ()) -> list[dict]:
        return [_row_to_dict(r) for r in self._r().execute(sql, tuple(params)).fetchall()]

    def query_one(self, sql: str, params: Iterable = ()) -> dict | None:
        r = self._r().execute(sql, tuple(params)).fetchone()
        return _row_to_dict(r) if r else None

    def close(self):
        with self._wlock:
            self._w.close()

    # ── 세션 ──
    def create_session(self, source: str, iface: str | None = None, bpf: str | None = None, note: str = "") -> int:
        with self._wlock:
            cur = self._w.execute("INSERT INTO sessions(started_at, source, iface, bpf_filter, note) VALUES (?,?,?,?,?)",
                                  (time.time(), source, iface, bpf, note))
            self._w.commit()
            return cur.lastrowid

    def end_session(self, sid: int, packets: int, dropped: int):
        with self._wlock:
            self._w.execute("UPDATE sessions SET ended_at=?, packets=?, dropped=? WHERE id=?",
                            (time.time(), packets, dropped, sid))
            self._w.commit()

    # ── 패킷 ──
    def insert_packets(self, session_id: int, recs: list[dict], max_packets: int) -> None:
        """레코드에 DB id 를 채워 넣는다 (rec['id'])."""
        if not recs:
            return
        with self._wlock:
            cur = self._w.cursor()
            sql = f"INSERT INTO packets({','.join(PACKET_COLS)}) VALUES ({','.join('?' * len(PACKET_COLS))})"
            for r in recs:
                cur.execute(sql, (session_id, r["source"], r["ts"], r["length"], r["src"], r["dst"], r["proto"],
                                  r["sport"], r["dport"], r["flags"], r["ttl"], r["direction"], r["service"],
                                  r.get("info"), r.get("friendly"), r["src_mac"], r["dst_mac"], r["first_layer"],
                                  r.get("raw")))
                r["id"] = cur.lastrowid
            self._w.commit()
            self._inserts_since_prune += len(recs)
            if self._inserts_since_prune >= 5000:
                self._inserts_since_prune = 0
                self._prune(max_packets)

    def _prune(self, max_packets: int):
        row = self._w.execute("SELECT MAX(id) FROM packets").fetchone()
        if row and row[0] and row[0] > max_packets:
            self._w.execute("DELETE FROM packets WHERE id <= ?", (row[0] - max_packets,))
            self._w.commit()

    def add_traffic(self, session_id: int, source: str, minutes: dict[int, dict]):
        if not minutes:
            return
        with self._wlock:
            for m, a in minutes.items():
                self._w.execute(
                    """INSERT INTO traffic_minute(minute, session_id, source, packets, bytes, up_bytes, down_bytes, tcp, udp, icmp, other)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(minute, session_id) DO UPDATE SET
                         packets=packets+excluded.packets, bytes=bytes+excluded.bytes,
                         up_bytes=up_bytes+excluded.up_bytes, down_bytes=down_bytes+excluded.down_bytes,
                         tcp=tcp+excluded.tcp, udp=udp+excluded.udp, icmp=icmp+excluded.icmp, other=other+excluded.other""",
                    (m, session_id, source, a["packets"], a["bytes"], a["up"], a["down"], a["tcp"], a["udp"], a["icmp"], a["other"]))
            self._w.commit()

    @staticmethod
    def _packet_where(session_id=None, before_id=None, after_id=None, proto=None, q=None, ip=None, src=None, dst=None, port=None):
        where, params = [], []
        if session_id is not None:
            where.append("session_id=?"); params.append(session_id)
        if before_id:
            where.append("id<?"); params.append(before_id)
        if after_id:
            where.append("id>?"); params.append(after_id)
        if proto:
            if proto == "DNS":
                where.append("service='DNS'")
            elif proto == "WEB":
                where.append("service IN ('HTTP','HTTPS','QUIC','HTTP-ALT','HTTPS-ALT')")
            else:
                where.append("proto=?"); params.append(proto)
        if ip:
            where.append("(src=? OR dst=?)"); params += [ip, ip]
        if src:
            where.append("src=?"); params.append(src)
        if dst:
            where.append("dst=?"); params.append(dst)
        if port is not None:
            where.append("(sport=? OR dport=?)"); params += [int(port), int(port)]
        if q:
            like = f"%{q}%"
            where.append("(src LIKE ? OR dst LIKE ? OR service LIKE ? OR info LIKE ? OR friendly LIKE ? OR CAST(sport AS TEXT)=? OR CAST(dport AS TEXT)=?)")
            params += [like, like, like, like, like, q, q]
        return where, params

    SORTABLE = {"id": "id", "ts": "ts", "length": "length", "src": "src", "dst": "dst", "proto": "proto", "sport": "sport", "dport": "dport"}

    def list_packets(self, session_id: int | None = None, before_id: int | None = None, limit: int = 200,
                     proto: str | None = None, q: str | None = None, after_id: int | None = None, ip: str | None = None,
                     src: str | None = None, dst: str | None = None, port: int | None = None,
                     sort: str = "id", order: str = "desc", offset: int = 0) -> list[dict]:
        where, params = self._packet_where(session_id, before_id, after_id, proto, q, ip, src, dst, port)
        sql = f"SELECT {LIST_COLS} FROM packets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        col = self.SORTABLE.get(sort, "id")
        sql += f" ORDER BY {col} {'ASC' if order == 'asc' else 'DESC'}, id DESC LIMIT ? OFFSET ?"
        params += [max(1, min(int(limit), 2000)), max(0, int(offset))]
        return self.query(sql, params)

    def count_packets(self, session_id: int | None = None, proto: str | None = None, q: str | None = None, ip: str | None = None,
                      src: str | None = None, dst: str | None = None, port: int | None = None) -> int:
        where, params = self._packet_where(session_id, None, None, proto, q, ip, src, dst, port)
        sql = "SELECT COUNT(*) FROM packets" + (" WHERE " + " AND ".join(where) if where else "")
        r = self._r().execute(sql, params).fetchone()
        return int(r[0])

    def ip_summary(self, ip: str, session_id: int | None = None) -> dict:
        """IP 상세 팝업용: 보낸/받은 패킷·바이트, 처음/마지막, 포트·상대 Top, 관련 이상 징후. 보관 중인 패킷 기준."""
        sf, params = ("", []) if session_id is None else (" AND session_id=?", [session_id])
        sent = self.query_one(f"SELECT COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes, MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM packets WHERE src=?{sf}", [ip] + params)
        recv = self.query_one(f"SELECT COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes, MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM packets WHERE dst=?{sf}", [ip] + params)
        ports = self.query(f"""SELECT dport AS port, proto, service, COUNT(*) AS packets, SUM(length) AS bytes FROM packets
                               WHERE dst=? AND dport IS NOT NULL{sf} GROUP BY dport, proto ORDER BY packets DESC LIMIT 8""", [ip] + params)
        peers = self.query(f"""SELECT peer, SUM(packets) AS packets, SUM(bytes) AS bytes FROM (
                                 SELECT dst AS peer, COUNT(*) AS packets, SUM(length) AS bytes FROM packets WHERE src=?{sf} GROUP BY dst
                                 UNION ALL SELECT src AS peer, COUNT(*) AS packets, SUM(length) AS bytes FROM packets WHERE dst=?{sf} GROUP BY src)
                               WHERE peer IS NOT NULL GROUP BY peer ORDER BY bytes DESC LIMIT 8""", [ip] + params + [ip] + params)
        protos = self.query(f"""SELECT proto, COUNT(*) AS packets FROM packets WHERE (src=? OR dst=?){sf} GROUP BY proto ORDER BY packets DESC""", [ip, ip] + params)
        anomalies = self.query("SELECT id, type, severity, status, detected_at, last_seen, count, source, explanation FROM anomalies WHERE src=? OR dst=? ORDER BY last_seen DESC LIMIT 10", (ip, ip))
        name = self.query_one("SELECT name FROM ip_names WHERE ip=?", (ip,))
        firsts = [x for x in (sent["first_ts"], recv["first_ts"]) if x]
        lasts = [x for x in (sent["last_ts"], recv["last_ts"]) if x]
        return {"ip": ip, "name": (name or {}).get("name"), "sent": sent, "received": recv, "ports": ports, "peers": peers, "protocols": protos,
                "anomalies": anomalies, "first_ts": min(firsts) if firsts else None, "last_ts": max(lasts) if lasts else None}

    def search(self, q: str, limit: int = 8) -> dict:
        """전역 검색: IP·도메인 이름·이상 징후."""
        like = f"%{q}%"
        ips = self.query("""SELECT ip, SUM(packets) AS packets FROM (
                              SELECT src AS ip, COUNT(*) AS packets FROM packets WHERE src LIKE ? GROUP BY src
                              UNION ALL SELECT dst AS ip, COUNT(*) AS packets FROM packets WHERE dst LIKE ? GROUP BY dst)
                            GROUP BY ip ORDER BY packets DESC LIMIT ?""", (like, like, limit))
        names = self.query("SELECT ip, name FROM ip_names WHERE name LIKE ? ORDER BY updated DESC LIMIT ?", (like, limit))
        anomalies = self.query("SELECT id, type, severity, status, last_seen, src, dst, source, explanation FROM anomalies WHERE src LIKE ? OR dst LIKE ? OR type LIKE ? OR explanation LIKE ? ORDER BY last_seen DESC LIMIT ?",
                               (like, like, like, like, limit))
        return {"ips": ips, "names": names, "anomalies": anomalies}

    def get_packet(self, pid: int) -> dict | None:
        r = self._r().execute("SELECT * FROM packets WHERE id=?", (pid,)).fetchone()
        return dict(r) if r else None

    def count_packets_from(self, ip: str, since: float) -> int:
        r = self._r().execute("SELECT COUNT(*) FROM packets WHERE src=? AND ts>=?", (ip, since)).fetchone()
        return int(r[0])

    def count_packets_to(self, ip: str, since: float) -> int:
        r = self._r().execute("SELECT COUNT(*) FROM packets WHERE dst=? AND ts>=?", (ip, since)).fetchone()
        return int(r[0])

    def ip_history(self, ip: str, limit: int = 50) -> dict:
        rows = self.query(f"SELECT {LIST_COLS} FROM packets WHERE src=? OR dst=? ORDER BY id DESC LIMIT ?", (ip, ip, limit))
        agg = self.query_one("""SELECT COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes, MIN(ts) AS first_ts, MAX(ts) AS last_ts
                                FROM packets WHERE src=? OR dst=?""", (ip, ip))
        ports = self.query("""SELECT proto, COALESCE(service,'') AS service, COUNT(*) AS packets FROM packets
                              WHERE src=? OR dst=? GROUP BY proto, service ORDER BY packets DESC LIMIT 10""", (ip, ip))
        return {"summary": agg, "services": ports, "recent": rows}

    # ── 이상 징후 ──
    def insert_anomaly(self, a: dict) -> int:
        cols = ("session_id", "source", "detected_at", "last_seen", "type", "severity", "src", "dst", "port", "protocol",
                "criterion", "threshold", "measured", "peak", "evidence", "explanation", "count", "status")
        vals = [json.dumps(a.get(c), ensure_ascii=False) if c in JSON_FIELDS else a.get(c) for c in cols]
        with self._wlock:
            cur = self._w.execute(f"INSERT INTO anomalies({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
            self._w.commit()
            return cur.lastrowid

    def update_row(self, table: str, rid: int, fields: dict):
        assert table in ("anomalies", "actions")
        if not fields:
            return
        sets, vals = [], []
        for k, v in fields.items():
            if not k.replace("_", "").isalnum():
                raise ValueError(k)
            sets.append(f"{k}=?")
            vals.append(json.dumps(v, ensure_ascii=False) if k in JSON_FIELDS else v)
        vals.append(rid)
        with self._wlock:
            self._w.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE id=?", vals)
            self._w.commit()

    def list_anomalies(self, status: str | None = None, limit: int = 200, include_test: bool = True,
                       since: float | None = None, until: float | None = None) -> list[dict]:
        where, params = [], []
        if status:
            where.append("status=?"); params.append(status)
        if not include_test:
            where.append("source='live'")
        if since:
            where.append("detected_at>=?"); params.append(since)
        if until:
            where.append("detected_at<?"); params.append(until)
        sql = "SELECT * FROM anomalies" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        return self.query(sql, params)

    def get_anomaly(self, aid: int) -> dict | None:
        return self.query_one("SELECT * FROM anomalies WHERE id=?", (aid,))

    # ── 조치 ──
    def insert_action(self, a: dict) -> int:
        cols = ("created_at", "anomaly_id", "action", "params", "trigger", "status", "simulated", "before_state",
                "result", "verification", "rollback_info", "expires_at")
        vals = [json.dumps(a.get(c), ensure_ascii=False) if c in JSON_FIELDS else a.get(c) for c in cols]
        with self._wlock:
            cur = self._w.execute(f"INSERT INTO actions({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
            self._w.commit()
            return cur.lastrowid

    def get_action(self, aid: int) -> dict | None:
        return self.query_one("SELECT * FROM actions WHERE id=?", (aid,))

    def list_actions(self, anomaly_id: int | None = None, limit: int = 100) -> list[dict]:
        if anomaly_id is not None:
            return self.query("SELECT * FROM actions WHERE anomaly_id=? ORDER BY id DESC LIMIT ?", (anomaly_id, limit))
        return self.query("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))

    # ── 건강 점수 이력 ──
    def insert_health(self, session_id: int | None, source: str | None, score: int, status: str, components: list):
        with self._wlock:
            self._w.execute("INSERT INTO health_history(ts, session_id, source, score, status, components) VALUES (?,?,?,?,?,?)",
                            (time.time(), session_id, source, score, status, json.dumps(components, ensure_ascii=False)))
            self._w.commit()

    # ── IP → 도메인 ──
    def upsert_names(self, names: dict[str, str]):
        if not names:
            return
        now = time.time()
        with self._wlock:
            self._w.executemany("INSERT INTO ip_names(ip, name, updated) VALUES (?,?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name, updated=excluded.updated",
                                [(ip, n, now) for ip, n in names.items()])
            self._w.commit()

    def load_names(self, limit: int = 20000) -> dict[str, str]:
        return {r["ip"]: r["name"] for r in self.query("SELECT ip, name FROM ip_names ORDER BY updated DESC LIMIT ?", (limit,))}

    # ── 리포트 ──
    @staticmethod
    def _src_filter(include_test: bool, col: str = "source") -> str:
        return "" if include_test else f" AND {col}='live'"

    def report(self, start: float, end: float, include_test: bool = False) -> dict[str, Any]:
        sf = self._src_filter(include_test)
        daily = self.query(f"""SELECT date(minute*60, 'unixepoch', 'localtime') AS day,
                                SUM(packets) AS packets, SUM(bytes) AS bytes, SUM(up_bytes) AS up_bytes, SUM(down_bytes) AS down_bytes
                               FROM traffic_minute WHERE minute>=? AND minute<? {sf} GROUP BY day ORDER BY day""",
                           (int(start // 60), int(end // 60) + 1))
        proto = self.query_one(f"""SELECT COALESCE(SUM(tcp),0) AS TCP, COALESCE(SUM(udp),0) AS UDP, COALESCE(SUM(icmp),0) AS ICMP,
                                   COALESCE(SUM(other),0) AS OTHER, COALESCE(SUM(packets),0) AS total, COALESCE(SUM(bytes),0) AS bytes
                                   FROM traffic_minute WHERE minute>=? AND minute<? {sf}""", (int(start // 60), int(end // 60) + 1))
        top_src = self.query(f"""SELECT src AS ip, COUNT(*) AS packets, SUM(length) AS bytes FROM packets
                                 WHERE ts>=? AND ts<? AND src IS NOT NULL {sf} GROUP BY src ORDER BY bytes DESC LIMIT 10""", (start, end))
        top_dst = self.query(f"""SELECT dst AS ip, COUNT(*) AS packets, SUM(length) AS bytes FROM packets
                                 WHERE ts>=? AND ts<? AND dst IS NOT NULL {sf} GROUP BY dst ORDER BY bytes DESC LIMIT 10""", (start, end))
        ports = self.query(f"""SELECT proto, service, COUNT(*) AS packets, SUM(length) AS bytes FROM packets
                               WHERE ts>=? AND ts<? AND service IS NOT NULL AND service != '' {sf}
                               GROUP BY proto, service ORDER BY bytes DESC LIMIT 12""", (start, end))
        anomalies = self.list_anomalies(limit=500, include_test=include_test, since=start, until=end)
        health = self.query(f"""SELECT ts, score, status FROM health_history WHERE ts>=? AND ts<? {sf}
                                ORDER BY ts""", (start, end))
        if len(health) > 400:  # 그래프용 다운샘플
            step = len(health) // 400 + 1
            health = health[::step]
        retained = self.query_one(f"SELECT MIN(ts) AS oldest FROM packets WHERE 1=1 {sf}")
        actions = self.query("SELECT id, created_at, anomaly_id, action, trigger, status, simulated, verification, rolled_back_at FROM actions WHERE created_at>=? AND created_at<? ORDER BY id DESC LIMIT 200", (start, end))
        return {"daily": daily, "protocols": proto, "top_src": top_src, "top_dst": top_dst, "ports": ports,
                "anomalies": anomalies, "health": health, "actions": actions, "packet_retention_oldest": (retained or {}).get("oldest")}

    def export_rows(self, kind: str, start: float, end: float, include_test: bool) -> list[dict]:
        sf = self._src_filter(include_test)
        if kind == "packets":
            return self.query(f"SELECT {LIST_COLS} FROM packets WHERE ts>=? AND ts<? {sf} ORDER BY id LIMIT 200000", (start, end))
        if kind == "traffic":
            return self.query(f"SELECT * FROM traffic_minute WHERE minute>=? AND minute<? {sf} ORDER BY minute",
                              (int(start // 60), int(end // 60) + 1))
        if kind == "anomalies":
            return self.list_anomalies(limit=100000, include_test=include_test, since=start, until=end)
        if kind == "actions":
            return self.query("SELECT * FROM actions WHERE created_at>=? AND created_at<? ORDER BY id", (start, end))
        if kind == "health":
            return self.query(f"SELECT ts, source, score, status, components FROM health_history WHERE ts>=? AND ts<? {sf} ORDER BY ts", (start, end))
        raise ValueError(kind)
