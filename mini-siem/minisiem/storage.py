"""SQLite persistence for events and alerts.

SQLite keeps the project dependency-free while still demonstrating a real
storage layer: indexed columns for the fields analysts filter on, plus a JSON
blob for the long tail of normalized fields.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    dataset     TEXT NOT NULL,
    action      TEXT,
    outcome     TEXT,
    source_ip   TEXT,
    user_name   TEXT,
    host_name   TEXT,
    message     TEXT,
    fields      TEXT NOT NULL,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_dataset   ON events(dataset);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user      ON events(user_name);

CREATE TABLE IF NOT EXISTS alerts (
    id             TEXT PRIMARY KEY,
    timestamp      TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    severity_score INTEGER NOT NULL,
    entity         TEXT,
    event_count    INTEGER NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    description    TEXT,
    tags           TEXT NOT NULL,
    mitre          TEXT NOT NULL,
    event_ids      TEXT NOT NULL,
    dataset        TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule      ON alerts(rule_id);
"""


class Storage:
    """Small wrapper around a SQLite database file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def initialize(self, reset: bool = False) -> None:
        self.connection.executescript(SCHEMA)
        if reset:
            self.connection.execute("DELETE FROM events")
            self.connection.execute("DELETE FROM alerts")
        self.connection.commit()

    def write(self, events: list[Event], alerts: list[Alert], reset: bool = True) -> None:
        self.initialize(reset=reset)
        event_rows = [
            (
                record["id"], record["timestamp"], record["dataset"], record["action"],
                record["outcome"], record["source_ip"], record["user_name"],
                record["host_name"], record["message"],
                json.dumps(record["fields"], ensure_ascii=False), record["raw"],
            )
            for record in (event.to_record() for event in events)
        ]
        self.connection.executemany(
            "INSERT INTO events (id, timestamp, dataset, action, outcome, source_ip, "
            "user_name, host_name, message, fields, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            event_rows,
        )
        alert_rows = [
            (
                record["id"], record["timestamp"], record["rule_id"], record["title"],
                record["severity"], record["severity_score"], record["entity"],
                record["event_count"], record["first_seen"], record["last_seen"],
                record["description"], json.dumps(record["tags"], ensure_ascii=False),
                json.dumps(record["mitre"], ensure_ascii=False),
                json.dumps(record["event_ids"], ensure_ascii=False), record["dataset"],
            )
            for record in (alert.to_record() for alert in alerts)
        ]
        self.connection.executemany(
            "INSERT INTO alerts (id, timestamp, rule_id, title, severity, severity_score, "
            "entity, event_count, first_seen, last_seen, description, tags, mitre, "
            "event_ids, dataset) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            alert_rows,
        )
        self.connection.commit()

    def load_events(self) -> list[Event]:
        rows = self.connection.execute(
            "SELECT id, timestamp, dataset, fields, raw FROM events ORDER BY timestamp"
        ).fetchall()
        return [
            Event.from_record({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "dataset": row["dataset"],
                "fields": json.loads(row["fields"]),
                "raw": row["raw"],
            })
            for row in rows
        ]

    def load_alerts(self) -> list[Alert]:
        rows = self.connection.execute(
            "SELECT * FROM alerts ORDER BY timestamp"
        ).fetchall()
        return [
            Alert.from_record({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "rule_id": row["rule_id"],
                "title": row["title"],
                "severity": row["severity"],
                "entity": row["entity"],
                "event_count": row["event_count"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "description": row["description"],
                "tags": json.loads(row["tags"]),
                "mitre": json.loads(row["mitre"]),
                "event_ids": json.loads(row["event_ids"]),
                "dataset": row["dataset"],
            })
            for row in rows
        ]

    def counts(self) -> tuple[int, int]:
        events = self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = self.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return int(events), int(alerts)
