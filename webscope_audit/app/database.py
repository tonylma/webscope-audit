import json
import sqlite3
from pathlib import Path
from typing import Any


class AuditDatabase:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    scope TEXT,
                    summary_json TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def save_analysis(self, result: dict[str, Any]) -> int:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True)
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.execute(
                "INSERT INTO analyses (target_url, collected_at, scope, summary_json) VALUES (?, ?, ?, ?)",
                (
                    result.get("target", ""),
                    result.get("collected_at", ""),
                    result.get("scope", ""),
                    payload,
                ),
            )
            connection.commit()
        return int(cursor.lastrowid)

    def list_history(self, limit: int = 10) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT id, target_url, collected_at, scope, summary_json FROM analyses ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": row[0],
                "target_url": row[1],
                "collected_at": row[2],
                "scope": row[3],
                "summary_json": row[4],
            }
            for row in rows
        ]
