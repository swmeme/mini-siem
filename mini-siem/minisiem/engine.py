"""Correlation engine.

The engine receives normalized events in chronological order and keeps one
sliding-window bucket per ``(rule, grouping key)``. That is the whole state
machine: no external database, no message queue, no daemon.

For every matching event it appends the event to the bucket, evicts events
older than the rule window, and checks the threshold. A per-bucket cooldown
prevents an ongoing attack from producing one alert per event.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import Alert, Event
from .rules import Rule


@dataclass
class _Bucket:
    events: deque[Event] = field(default_factory=deque)
    last_alert: datetime | None = None


class DetectionEngine:
    """Evaluate a set of rules against a stream of events."""

    def __init__(self, rules: list[Rule], cooldown_factor: float = 1.0) -> None:
        if cooldown_factor <= 0:
            raise ValueError("cooldown_factor must be greater than zero")
        self.rules = [rule for rule in rules if rule.enabled]
        self.cooldown_factor = cooldown_factor
        self._buckets: dict[tuple[str, str], _Bucket] = {}

    def process(self, events: list[Event]) -> list[Alert]:
        """Return alerts for chronologically sorted *events*."""
        alerts: list[Alert] = []
        for event in events:
            for rule in self.rules:
                if not rule.matches(event):
                    continue

                # Ungrouped single-event rules do not need state at all.
                if rule.count == 1 and not rule.group_by:
                    alerts.append(rule.build_alert([event]))
                    continue

                key = rule.group_key(event)
                if key is None:
                    continue

                bucket = self._buckets.setdefault((rule.id, key), _Bucket())
                bucket.events.append(event)
                self._evict(rule, bucket, event.timestamp)

                if not self._threshold_reached(rule, bucket):
                    continue
                if not self._cooldown_elapsed(rule, bucket, event.timestamp):
                    continue

                bucket.last_alert = event.timestamp
                alerts.append(rule.build_alert(list(bucket.events)))

        return alerts

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _evict(rule: Rule, bucket: _Bucket, now: datetime) -> None:
        if rule.window_seconds <= 0:
            return
        cutoff = now - timedelta(seconds=rule.window_seconds)
        while bucket.events and bucket.events[0].timestamp < cutoff:
            bucket.events.popleft()

    @staticmethod
    def _threshold_reached(rule: Rule, bucket: _Bucket) -> bool:
        if rule.distinct_by:
            values = {
                event.get(rule.distinct_by)
                for event in bucket.events
                if event.get(rule.distinct_by) not in (None, "")
            }
            return len(values) >= rule.count
        return len(bucket.events) >= rule.count

    def _cooldown_elapsed(self, rule: Rule, bucket: _Bucket, now: datetime) -> bool:
        if bucket.last_alert is None:
            return True
        width = rule.cooldown * self.cooldown_factor
        return (now - bucket.last_alert).total_seconds() >= width
