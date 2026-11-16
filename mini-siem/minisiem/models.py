"""Shared data model: normalized events and generated alerts.

Every log line that the pipeline understands becomes an :class:`Event`.
Events carry *flat, dotted field names* (Elastic Common Schema style), e.g.
``source.ip`` or ``event.action``. Keeping fields flat makes rules trivial to
read and evaluate, and avoids a schema migration every time a new field is
needed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Ordered from least to most severe. The tuple order is used by --fail-on.
SEVERITY_SCORE: dict[str, int] = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

SEVERITIES = tuple(SEVERITY_SCORE)


def new_id(prefix: str) -> str:
    """Return a short, unique identifier such as ``evt-9f3c1a2b4d5e``."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def iso(timestamp: datetime) -> str:
    """Serialize a datetime as UTC ISO-8601 with a trailing ``Z``."""
    return (
        timestamp.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


@dataclass
class Event:
    """A single normalized log record."""

    timestamp: datetime
    dataset: str
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    id: str = field(default_factory=lambda: new_id("evt"))

    def get(self, path: str, default=None) -> str | None:
        return self.fields.get(path, default)

    def to_record(self) -> dict:
        """Shape used by the SQLite storage layer."""
        return {
            "id": self.id,
            "timestamp": iso(self.timestamp),
            "dataset": self.dataset,
            "action": self.fields.get("event.action"),
            "outcome": self.fields.get("event.outcome"),
            "source_ip": self.fields.get("source.ip"),
            "user_name": self.fields.get("user.name"),
            "host_name": self.fields.get("host.name"),
            "message": self.fields.get("message"),
            "fields": self.fields,
            "raw": self.raw,
        }

    @classmethod
    def from_record(cls, record: dict) -> "Event":
        return cls(
            id=record["id"],
            timestamp=datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")),
            dataset=record["dataset"],
            fields=dict(record["fields"]),
            raw=record.get("raw", ""),
        )


@dataclass
class Alert:
    """A detection raised by a rule."""

    rule_id: str
    title: str
    severity: str
    timestamp: datetime
    entity: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    dataset: str = ""
    id: str = field(default_factory=lambda: new_id("alt"))

    @property
    def severity_score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 0)

    def to_record(self) -> dict:
        return {
            "id": self.id,
            "timestamp": iso(self.timestamp),
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "entity": self.entity,
            "event_count": self.event_count,
            "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen),
            "description": self.description,
            "tags": self.tags,
            "mitre": self.mitre,
            "event_ids": self.event_ids,
            "dataset": self.dataset,
        }

    @classmethod
    def from_record(cls, record: dict) -> "Alert":
        return cls(
            id=record["id"],
            rule_id=record["rule_id"],
            title=record["title"],
            severity=record["severity"],
            timestamp=datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")),
            entity=record["entity"],
            event_count=int(record["event_count"]),
            first_seen=datetime.fromisoformat(record["first_seen"].replace("Z", "+00:00")),
            last_seen=datetime.fromisoformat(record["last_seen"].replace("Z", "+00:00")),
            description=record.get("description", ""),
            tags=list(record.get("tags", [])),
            mitre=list(record.get("mitre", [])),
            event_ids=list(record.get("event_ids", [])),
            dataset=record.get("dataset", ""),
        )
