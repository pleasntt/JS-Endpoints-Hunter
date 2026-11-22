from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import ScanResult


class Storage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def init(self) -> None:
        with self._session() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    input_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL DEFAULT '',
                    stats_json TEXT NOT NULL DEFAULT '{}',
                    options_json TEXT NOT NULL DEFAULT '{}',
                    artifacts_json TEXT NOT NULL DEFAULT '{}',
                    raw_files_json TEXT NOT NULL DEFAULT '[]',
                    dependencies_json TEXT NOT NULL DEFAULT '[]',
                    hosts_json TEXT NOT NULL DEFAULT '[]',
                    errors_json TEXT NOT NULL DEFAULT '[]',
                    show_secrets INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    line INTEGER NOT NULL DEFAULT 0,
                    data_json TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
                """)

    def create_scan(self, input_type: str, target: str, options: dict[str, Any]) -> int:
        with self._session() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans(input_type, target, status, started_at, options_json)
                VALUES (?, ?, 'queued', datetime('now'), ?)
                """,
                (input_type, target, json.dumps(options, ensure_ascii=False)),
            )
            rowid = cursor.lastrowid
            if rowid is None:
                raise RuntimeError("sqlite did not return a scan id")
            return int(rowid)

    def update_status(self, scan_id: int, status: str, error: str = "") -> None:
        with self._session() as connection:
            connection.execute(
                "UPDATE scans SET status = ?, errors_json = ? WHERE id = ?",
                (status, json.dumps([error] if error else [], ensure_ascii=False), scan_id),
            )

    def save_result(self, result: ScanResult, show_secrets: bool = False) -> None:
        payload = result.to_dict(show_secrets=show_secrets)
        surface: dict[str, Any] = {
            "stats_json": json.dumps(payload["stats"], ensure_ascii=False),
            "options_json": json.dumps(payload["options"], ensure_ascii=False),
            "artifacts_json": json.dumps(payload["artifacts"], ensure_ascii=False),
            "raw_files_json": json.dumps(payload["raw_files"], ensure_ascii=False),
            "dependencies_json": json.dumps(payload["dependencies"], ensure_ascii=False),
            "hosts_json": json.dumps(payload["hosts"], ensure_ascii=False),
            "errors_json": json.dumps(payload["errors"], ensure_ascii=False),
            "show_secrets": 1 if show_secrets else 0,
        }
        with self._session() as connection:
            connection.execute(
                """
                UPDATE scans SET status = ?, finished_at = ?, stats_json = ?,
                    options_json = ?, artifacts_json = ?, raw_files_json = ?,
                    dependencies_json = ?, hosts_json = ?, errors_json = ?,
                    show_secrets = ? WHERE id = ?
                """,
                (
                    result.status,
                    result.finished_at,
                    surface["stats_json"],
                    surface["options_json"],
                    surface["artifacts_json"],
                    surface["raw_files_json"],
                    surface["dependencies_json"],
                    surface["hosts_json"],
                    surface["errors_json"],
                    surface["show_secrets"],
                    result.scan_id,
                ),
            )
            connection.execute("DELETE FROM findings WHERE scan_id = ?", (result.scan_id,))
            for finding in payload["findings"]:
                connection.execute(
                    """
                    INSERT INTO findings(scan_id, fingerprint, kind, value, source, line, data_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scan_id,
                        finding["fingerprint"],
                        finding["kind"],
                        finding["value"],
                        finding["source"],
                        finding["line"],
                        json.dumps(finding, ensure_ascii=False),
                    ),
                )

    def _scan_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "input_type": row["input_type"],
            "target": row["target"],
            "status": row["status"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "stats": json.loads(row["stats_json"] or "{}"),
            "artifacts": json.loads(row["artifacts_json"] or "{}"),
            "show_secrets": bool(row["show_secrets"]),
        }

    def list_scans(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._scan_row(row) for row in rows]

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._session() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            finding_rows = connection.execute(
                "SELECT data_json FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        scan = self._scan_row(row)
        return {
            "scan": scan,
            "findings": [json.loads(item["data_json"]) for item in finding_rows],
            "raw_files": json.loads(row["raw_files_json"] or "[]"),
            "dependencies": json.loads(row["dependencies_json"] or "[]"),
            "hosts": json.loads(row["hosts_json"] or "[]"),
            "errors": json.loads(row["errors_json"] or "[]"),
            "options": json.loads(row["options_json"] or "{}"),
        }

    def delete_scan(self, scan_id: int) -> bool:
        with self._session() as connection:
            cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0

    def diff_scans(self, left_id: int, right_id: int) -> dict[str, Any]:
        left = self.get_scan(left_id)
        right = self.get_scan(right_id)
        if left is None or right is None:
            return {"error": "scan not found", "added": [], "removed": []}

        def endpoints(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
            result: dict[str, dict[str, Any]] = {}
            for finding in data["findings"]:
                if finding.get("kind") == "secret":
                    continue
                key = f"{finding.get('method', '')}|{finding.get('value', '')}"
                result[key] = finding
            return result

        before = endpoints(left)
        after = endpoints(right)
        added = [after[key] for key in sorted(after.keys() - before.keys())]
        removed = [before[key] for key in sorted(before.keys() - after.keys())]
        return {
            "from": left_id,
            "to": right_id,
            "added": added,
            "removed": removed,
            "common": len(before.keys() & after.keys()),
        }
