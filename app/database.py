"""Tiny SQLite layer. A new connection per call keeps things simple and
safe with FastAPI's thread pool - the app is nowhere near busy enough for
connection pooling to matter."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    status       TEXT NOT NULL,
    source       TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    detected_by  TEXT NOT NULL DEFAULT 'analyst',
    attacker_ip  TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    resolved_at  TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER,
    action       TEXT NOT NULL,
    actor        TEXT NOT NULL,
    details      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
"""

UPDATABLE_FIELDS = ("title", "severity", "status", "source", "description")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def ping(self) -> bool:
        try:
            with self._conn() as conn:
                conn.execute("SELECT 1")
            return True
        except sqlite3.Error:
            return False

    # --- incidents -------------------------------------------------------

    def create_incident(self, data: dict, detected_by: str = "analyst", attacker_ip: str | None = None) -> dict:
        now = utc_now()
        resolved_at = now if data.get("status") == "RESOLVED" else None
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO incidents
                   (title, severity, status, source, description, detected_by,
                    attacker_ip, created_at, updated_at, resolved_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    data["title"], data["severity"], data.get("status", "OPEN"),
                    data["source"], data.get("description", ""), detected_by,
                    attacker_ip, now, now, resolved_at,
                ),
            )
            new_id = cur.lastrowid
        return self.get_incident(new_id)

    def get_incident(self, incident_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return dict(row) if row else None

    def list_incidents(self, severity: str | None = None, status: str | None = None,
                       source: str | None = None) -> list[dict]:
        # filters are fixed column names, values always go through placeholders
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if source:
            clauses.append("source LIKE ?")
            params.append(f"%{source}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        # Bandit B608 reviewed: only the fixed clauses above end up in the string,
        # every user-supplied value is bound through a ? placeholder
        query = f"SELECT * FROM incidents {where} ORDER BY id DESC"  # nosec B608
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_incident(self, incident_id: int, changes: dict) -> dict | None:
        current = self.get_incident(incident_id)
        if current is None:
            return None
        changes = {k: v for k, v in changes.items() if k in UPDATABLE_FIELDS and v is not None}
        if not changes:
            return current

        now = utc_now()
        changes["updated_at"] = now
        if changes.get("status") == "RESOLVED" and current["status"] != "RESOLVED":
            changes["resolved_at"] = now
        elif "status" in changes and changes["status"] != "RESOLVED":
            changes["resolved_at"] = None

        # Bandit B608 reviewed: column names come from the UPDATABLE_FIELDS
        # whitelist, the values are bound through ? placeholders
        assignments = ", ".join(f"{col} = ?" for col in changes)
        with self._conn() as conn:
            conn.execute(
                f"UPDATE incidents SET {assignments} WHERE id = ?",  # nosec B608
                (*changes.values(), incident_id),
            )
        return self.get_incident(incident_id)

    def delete_incident(self, incident_id: int) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        return cur.rowcount > 0

    def recent_auto_incident(self, title: str, attacker_ip: str, since_iso: str) -> dict | None:
        """Used to stop one noisy attacker from creating hundreds of incidents."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM incidents
                   WHERE detected_by = 'auto' AND title = ? AND attacker_ip = ?
                     AND status != 'RESOLVED' AND created_at >= ?
                   ORDER BY id DESC LIMIT 1""",
                (title, attacker_ip, since_iso),
            ).fetchone()
        return dict(row) if row else None

    def counts(self) -> dict:
        with self._conn() as conn:
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM incidents WHERE status != 'RESOLVED' GROUP BY severity"
            ).fetchall()
            by_status = conn.execute(
                "SELECT status, COUNT(*) AS n FROM incidents GROUP BY status"
            ).fetchall()
            auto = conn.execute(
                "SELECT COUNT(*) AS n FROM incidents WHERE detected_by = 'auto'"
            ).fetchone()
        return {
            "open_by_severity": {r["severity"]: r["n"] for r in by_severity},
            "by_status": {r["status"]: r["n"] for r in by_status},
            "auto_detected": auto["n"],
        }

    # --- audit log -------------------------------------------------------

    def add_audit(self, action: str, actor: str, incident_id: int | None = None, details: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (incident_id, action, actor, details, created_at) VALUES (?, ?, ?, ?, ?)",
                (incident_id, action, actor, details, utc_now()),
            )

    def list_audit(self, limit: int = 100) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
