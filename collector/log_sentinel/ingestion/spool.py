"""Local SQLite store for file tail offsets and offline retry queue."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time
from typing import Any


@dataclass(frozen=True, slots=True)
class FileCursor:
    """Saved file offset and inode for crash-safe log tailing."""

    file_path: str
    inode: int
    byte_offset: int
    line_number: int


@dataclass(frozen=True, slots=True)
class QueuedBatch:
    """Serialized ingestion payload waiting for delivery."""

    batch_id: int
    payload: dict[str, Any]
    attempts: int
    next_retry_at: float


def compute_backoff_seconds(attempts: int) -> float:
    """Exponential retry delay capped at 300 seconds (5 minutes)."""
    return float(min(300, 2 ** min(max(1, attempts), 9)))


class LocalSpool:
    """Persists tailer positions and unsent batches across restarts and network drops."""

    def __init__(self, db_path: Path | str, max_queued_batches: int = 1000) -> None:
        self.db_path = Path(db_path)
        self.max_queued_batches = max_queued_batches
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS file_offsets (
                file_path TEXT PRIMARY KEY,
                inode INTEGER NOT NULL,
                byte_offset INTEGER NOT NULL,
                line_number INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_json TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_retry_at REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_cursor(self, file_path: Path | str) -> FileCursor | None:
        row = self._conn.execute(
            "SELECT file_path, inode, byte_offset, line_number FROM file_offsets WHERE file_path = ?",
            (str(file_path),),
        ).fetchone()
        if not row:
            return None
        return FileCursor(
            file_path=row[0],
            inode=int(row[1]),
            byte_offset=int(row[2]),
            line_number=int(row[3]),
        )

    def save_cursor(
        self, file_path: Path | str, inode: int, byte_offset: int, line_number: int
    ) -> None:
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._conn.execute(
            """
            INSERT INTO file_offsets (file_path, inode, byte_offset, line_number, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                inode = excluded.inode,
                byte_offset = excluded.byte_offset,
                line_number = excluded.line_number,
                updated_at = excluded.updated_at
            """,
            (str(file_path), inode, byte_offset, line_number, now_iso),
        )
        self._conn.commit()

    def enqueue_batch(self, payload: dict[str, Any]) -> int:
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        encoded = json.dumps(payload, separators=(",", ":"))
        cur = self._conn.execute(
            """
            INSERT INTO pending_batches (payload_json, attempts, next_retry_at, created_at)
            VALUES (?, 0, ?, ?)
            """,
            (encoded, time.time(), now_iso),
        )
        # Bound disk usage if offline for a very long period
        self._conn.execute(
            """
            DELETE FROM pending_batches
            WHERE id NOT IN (
                SELECT id FROM pending_batches ORDER BY id DESC LIMIT ?
            )
            """,
            (self.max_queued_batches,),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def get_due_batches(self, limit: int = 10, now_ts: float | None = None) -> list[QueuedBatch]:
        current = time.time() if now_ts is None else now_ts
        rows = self._conn.execute(
            """
            SELECT id, payload_json, attempts, next_retry_at
            FROM pending_batches
            WHERE next_retry_at <= ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (current, limit),
        ).fetchall()
        return [
            QueuedBatch(
                batch_id=int(r[0]),
                payload=json.loads(r[1]),
                attempts=int(r[2]),
                next_retry_at=float(r[3]),
            )
            for r in rows
        ]

    def mark_delivered(self, batch_id: int) -> None:
        self._conn.execute("DELETE FROM pending_batches WHERE id = ?", (batch_id,))
        self._conn.commit()

    def schedule_retry(self, batch_id: int, attempts: int, now_ts: float | None = None) -> float:
        next_attempts = attempts + 1
        delay = compute_backoff_seconds(next_attempts)
        next_at = (time.time() if now_ts is None else now_ts) + delay
        self._conn.execute(
            "UPDATE pending_batches SET attempts = ?, next_retry_at = ? WHERE id = ?",
            (next_attempts, next_at, batch_id),
        )
        self._conn.commit()
        return next_at

    def pending_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM pending_batches").fetchone()
        return int(row[0]) if row else 0
