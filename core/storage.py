from __future__ import annotations

import json
import sqlite3

# Esquema relacional: cada entidad tiene su tabla con indice por session_id.
# Se persiste por ENTIDAD (no snapshot completo en cada mutacion) y las
# escrituras van en transacciones SQLite (WAL, synchronous=NORMAL).
_TABLES: dict[str, str] = {
    "targets": "id TEXT PRIMARY KEY, data TEXT",
    "sessions": "id TEXT PRIMARY KEY, data TEXT",
    "results": "session_id TEXT, id TEXT, data TEXT, PRIMARY KEY(session_id, id)",
    "findings": "session_id TEXT, id TEXT, data TEXT, PRIMARY KEY(session_id, id)",
    "investigations": "session_id TEXT, id TEXT, data TEXT, PRIMARY KEY(session_id, id)",
    "alerts": "session_id TEXT, id TEXT, data TEXT, PRIMARY KEY(session_id, id)",
    "incidents": "session_id TEXT, id TEXT, data TEXT, PRIMARY KEY(session_id, id)",
    "rules": "session_id TEXT, id TEXT, data TEXT, PRIMARY KEY(session_id, id)",
    "iocs": "session_id TEXT, id TEXT, data TEXT, PRIMARY KEY(session_id, id)",
    "nodes": (
        "id TEXT PRIMARY KEY, session_id TEXT, kind TEXT, state TEXT, "
        "confidence REAL, last_seen TEXT, data TEXT"
    ),
    "links": "session_id TEXT, source TEXT, target TEXT, kind TEXT, data TEXT",
    "audit": "seq INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT",
}

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_nodes_session ON nodes(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind)",
    "CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_investigations_session ON investigations(session_id)",
]

# Tabla KV legacy (solo para migracion de snapshots antiguos)
_LEGACY_KV = "kv (key TEXT PRIMARY KEY, value TEXT)"


class Storage:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        for name, ddl in _TABLES.items():
            self._conn.execute(f"CREATE TABLE IF NOT EXISTS {name} ({ddl})")
        self._conn.execute(f"CREATE TABLE IF NOT EXISTS {_LEGACY_KV}")
        for index in _INDEXES:
            self._conn.execute(index)
        self._conn.commit()

    # ------------------------------------------------------------------
    # escritura por entidad (transaccion por llamada)
    # ------------------------------------------------------------------
    def upsert(self, kind: str, record: dict) -> None:
        data = json.dumps(record, ensure_ascii=False)
        with self._conn:
            if kind == "target":
                self._conn.execute(
                    "INSERT OR REPLACE INTO targets (id, data) VALUES (?, ?)",
                    (record["id"], data),
                )
            elif kind == "session":
                self._conn.execute(
                    "INSERT OR REPLACE INTO sessions (id, data) VALUES (?, ?)",
                    (record["id"], data),
                )
            elif kind == "result":
                self._conn.execute(
                    "INSERT OR REPLACE INTO results (session_id, id, data) VALUES (?, ?, ?)",
                    (record["session_id"], record["id"], data),
                )
            elif kind == "finding":
                self._conn.execute(
                    "INSERT OR REPLACE INTO findings (session_id, id, data) VALUES (?, ?, ?)",
                    (record["session_id"], record["id"], data),
                )
            elif kind == "investigation":
                self._conn.execute(
                    "INSERT OR REPLACE INTO investigations (session_id, id, data) VALUES (?, ?, ?)",
                    (record["session_id"], record["id"], data),
                )
            elif kind == "alert":
                self._conn.execute(
                    "INSERT OR REPLACE INTO alerts (session_id, id, data) VALUES (?, ?, ?)",
                    (record["session_id"], record["id"], data),
                )
            elif kind == "incident":
                self._conn.execute(
                    "INSERT OR REPLACE INTO incidents (session_id, id, data) VALUES (?, ?, ?)",
                    (record["session_id"], record["id"], data),
                )
            elif kind == "rule":
                self._conn.execute(
                    "INSERT OR REPLACE INTO rules (session_id, id, data) VALUES (?, ?, ?)",
                    (record["session_id"], record["id"], data),
                )
            elif kind == "ioc":
                self._conn.execute(
                    "INSERT OR REPLACE INTO iocs (session_id, id, data) VALUES (?, ?, ?)",
                    (record["session_id"], record["id"], data),
                )
            elif kind == "node":
                self._conn.execute(
                    "INSERT OR REPLACE INTO nodes (id, session_id, kind, state, confidence, last_seen, data) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        record["id"],
                        record["session_id"],
                        record["kind"],
                        record["state"],
                        record["confidence"],
                        record.get("last_seen", ""),
                        data,
                    ),
                )
            elif kind == "link":
                self._conn.execute(
                    "DELETE FROM links WHERE session_id = ? AND source = ? AND target = ?",
                    (record["session_id"], record["source"], record["target"]),
                )
                self._conn.execute(
                    "INSERT INTO links (session_id, source, target, kind, data) VALUES (?, ?, ?, ?, ?)",
                    (
                        record["session_id"],
                        record["source"],
                        record["target"],
                        record["kind"],
                        data,
                    ),
                )
            elif kind == "audit":
                self._conn.execute("INSERT INTO audit (entry) VALUES (?)", (data,))
            else:
                raise ValueError(f"tipo desconocido para persistir: {kind}")

    def delete_nodes(self, node_ids: list[str]) -> None:
        if not node_ids:
            return
        with self._conn:
            self._conn.executemany(
                "DELETE FROM nodes WHERE id = ?", [(node_id,) for node_id in node_ids]
            )

    # ------------------------------------------------------------------
    # lectura
    # ------------------------------------------------------------------
    def load_all(self, kind: str) -> list[dict]:
        column = "entry" if kind == "audit" else "data"
        rows = self._conn.execute(f"SELECT {column} FROM {kind}").fetchall()
        return [json.loads(row[0]) for row in rows]

    # ------------------------------------------------------------------
    # migracion desde el snapshot legacy (kv)
    # ------------------------------------------------------------------
    def _get_legacy(self, key: str) -> dict | list | None:
        row = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def migrate_legacy(self) -> bool:
        """Si existen datos en el snapshot antiguo y las tablas estan vacias,
        migra y elimina el snapshot legacy."""
        snapshot = self._get_legacy("snapshot")
        audit = self._get_legacy("audit")
        if not snapshot and not audit:
            return False
        if snapshot and not self._conn.execute("SELECT 1 FROM targets LIMIT 1").fetchone():
            for target in snapshot.get("targets", []):
                self.upsert("target", target)
            for session in snapshot.get("sessions", []):
                self.upsert("session", session)
            for result in snapshot.get("results", []):
                self.upsert("result", result)
            for finding in snapshot.get("findings", []):
                self.upsert("finding", finding)
            for investigation in snapshot.get("investigations", []):
                self.upsert("investigation", investigation)
            for alert in snapshot.get("alerts", []):
                self.upsert("alert", alert)
            for incident in snapshot.get("incidents", []):
                self.upsert("incident", incident)
            for rule in snapshot.get("rules", []):
                self.upsert("rule", rule)
            for ioc in snapshot.get("iocs", []):
                self.upsert("ioc", ioc)
            for node in snapshot.get("nodes", []):
                self.upsert("node", node)
            for link in snapshot.get("links", []):
                self.upsert("link", link)
        if audit:
            with self._conn:
                for entry in audit:
                    self._conn.execute(
                        "INSERT INTO audit (entry) VALUES (?)",
                        (json.dumps(entry, ensure_ascii=False),),
                    )
        with self._conn:
            self._conn.execute("DELETE FROM kv WHERE key IN ('snapshot', 'audit')")
        return True

    def close(self) -> None:
        self._conn.close()
