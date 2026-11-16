"""Detection rules: loading, validation and evaluation.

A rule is a small JSON document. Two families are supported:

* **single-event rules** - fire once per matching event (optionally grouped and
  rate-limited by a cooldown);
* **threshold rules** - fire when *N* matching events occur inside a sliding
  time window for the same grouping key. ``distinct_by`` switches the count
  from "N events" to "N different values of a field", which is how password
  spraying is distinguished from brute force.

The schema is documented in docs/RULES.md.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import SEVERITIES, Alert, Event


class RuleError(ValueError):
    """Raised when a rule file is malformed or internally inconsistent."""


def _value_matches(actual: str | None, expected: Any) -> bool:
    """Evaluate one match condition against a normalized field value."""
    if actual is None:
        return False
    if isinstance(expected, list):
        return any(_value_matches(actual, item) for item in expected)
    if isinstance(expected, dict):
        if "regex" in expected:
            try:
                return re.search(str(expected["regex"]), str(actual), re.IGNORECASE) is not None
            except re.error:
                return False
        if "not" in expected:
            return not _value_matches(actual, expected["not"])
        return False
    return str(actual) == str(expected)


@dataclass
class Rule:
    id: str
    title: str
    severity: str = "medium"
    description: str = ""
    dataset: str | None = None
    match: dict[str, Any] = field(default_factory=dict)
    group_by: list[str] = field(default_factory=list)
    count: int = 1
    window_seconds: int = 0
    distinct_by: str | None = None
    cooldown_seconds: int | None = None
    tags: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    enabled: bool = True

    # -- behaviour ---------------------------------------------------------

    def matches(self, event: Event) -> bool:
        if self.dataset is not None and event.dataset != self.dataset:
            return False
        return all(_value_matches(event.get(path), expected) for path, expected in self.match.items())

    def group_key(self, event: Event) -> str | None:
        """Return the correlation key, or ``None`` if a field is missing."""
        if not self.group_by:
            return ""
        values = [event.get(path) for path in self.group_by]
        if any(value in (None, "") for value in values):
            return None
        return "|".join(values)  # type: ignore[arg-type]

    def entity_label(self, event: Event) -> str:
        if self.group_by:
            return ", ".join(f"{path}={event.get(path)}" for path in self.group_by)
        return event.get("host.name") or event.dataset

    @property
    def cooldown(self) -> int:
        if self.cooldown_seconds is not None:
            return self.cooldown_seconds
        return self.window_seconds or 60

    @property
    def kind(self) -> str:
        if self.count <= 1 and not self.group_by:
            return "single event"
        if self.distinct_by:
            return f"threshold / {self.count} distinct {self.distinct_by}"
        if self.count > 1:
            return f"threshold / {self.count} in {self.window_seconds}s"
        return "single event / grouped"

    def build_alert(self, events: list[Event]) -> Alert:
        if not events:  # pragma: no cover - defensive
            raise ValueError("cannot build an alert without events")
        first, last = events[0], events[-1]
        return Alert(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            timestamp=last.timestamp,
            entity=self.entity_label(last),
            event_count=len(events),
            first_seen=first.timestamp,
            last_seen=last.timestamp,
            description=self.description,
            tags=list(self.tags),
            mitre=list(self.mitre),
            event_ids=[event.id for event in events[-20:]],
            dataset=last.dataset,
        )

    # -- construction ------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        if not isinstance(data, dict):
            raise RuleError("rule must be a JSON object")
        rule_id = data.get("id")
        title = data.get("title")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise RuleError("'id' is required and must be a non-empty string")
        if not isinstance(title, str) or not title.strip():
            raise RuleError("'title' is required and must be a non-empty string")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", rule_id):
            raise RuleError("'id' may only contain letters, digits, '_', '.' and '-'")

        severity = data.get("severity", "medium")
        if severity not in SEVERITIES:
            raise RuleError(f"invalid severity {severity!r}; use one of {', '.join(SEVERITIES)}")

        match = data.get("match")
        if not isinstance(match, dict) or not match:
            raise RuleError("'match' must be a non-empty object of field -> value conditions")
        for path, expected in match.items():
            if not isinstance(path, str) or not path:
                raise RuleError("match field names must be non-empty strings")
            if isinstance(expected, dict):
                if set(expected) - {"regex", "not"}:
                    raise RuleError(f"unsupported operator in match condition for {path!r}")
                if "regex" in expected:
                    try:
                        re.compile(str(expected["regex"]))
                    except re.error as exc:
                        raise RuleError(f"invalid regex for {path!r}: {exc}") from exc
            elif not isinstance(expected, (str, int, list)):
                raise RuleError(f"unsupported value for {path!r}: {type(expected).__name__}")

        group_by = data.get("group_by", [])
        if not isinstance(group_by, list) or not all(isinstance(item, str) and item for item in group_by):
            raise RuleError("'group_by' must be a list of non-empty field names")

        threshold = data.get("threshold", {})
        if not isinstance(threshold, dict):
            raise RuleError("'threshold' must be an object")
        count = threshold.get("count", 1)
        window_seconds = threshold.get("window_seconds", 0)
        distinct_by = threshold.get("distinct_by")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RuleError("'threshold.count' must be an integer >= 1")
        if not isinstance(window_seconds, int) or isinstance(window_seconds, bool) or window_seconds < 0:
            raise RuleError("'threshold.window_seconds' must be an integer >= 0")
        if count > 1 and window_seconds <= 0:
            raise RuleError("threshold rules with count > 1 require 'window_seconds' > 0")
        if count > 1 and not group_by:
            raise RuleError("threshold rules with count > 1 require at least one 'group_by' field")
        if distinct_by is not None and (not isinstance(distinct_by, str) or not distinct_by):
            raise RuleError("'threshold.distinct_by' must be a non-empty field name")
        if distinct_by is not None and count <= 1:
            raise RuleError("'threshold.distinct_by' requires count > 1")

        cooldown_seconds = data.get("cooldown_seconds")
        if cooldown_seconds is not None and (
            not isinstance(cooldown_seconds, int) or isinstance(cooldown_seconds, bool) or cooldown_seconds < 0
        ):
            raise RuleError("'cooldown_seconds' must be an integer >= 0")

        tags = data.get("tags", [])
        mitre = data.get("mitre", [])
        for name, value in (("tags", tags), ("mitre", mitre)):
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise RuleError(f"'{name}' must be a list of strings")

        dataset = data.get("dataset")
        if dataset is not None and not isinstance(dataset, str):
            raise RuleError("'dataset' must be a string")

        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuleError("'enabled' must be true or false")

        description = data.get("description", "")
        if not isinstance(description, str):
            raise RuleError("'description' must be a string")

        return cls(
            id=rule_id,
            title=title.strip(),
            severity=severity,
            description=description.strip(),
            dataset=dataset,
            match=match,
            group_by=group_by,
            count=count,
            window_seconds=window_seconds,
            distinct_by=distinct_by,
            cooldown_seconds=cooldown_seconds,
            tags=tags,
            mitre=mitre,
            enabled=enabled,
        )


def load_rules(directory: str | Path) -> list[Rule]:
    """Load every ``*.json`` rule in *directory*, sorted by filename."""
    directory = Path(directory)
    if not directory.is_dir():
        raise RuleError(f"rules directory not found: {directory}")
    rules: list[Rule] = []
    seen: dict[str, Path] = {}
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuleError(f"{path.name}: invalid JSON ({exc})") from exc
        try:
            rule = Rule.from_dict(data)
        except RuleError as exc:
            raise RuleError(f"{path.name}: {exc}") from exc
        if rule.id in seen:
            raise RuleError(f"duplicate rule id {rule.id!r} in {path.name} and {seen[rule.id].name}")
        seen[rule.id] = path
        rules.append(rule)
    if not rules:
        raise RuleError(f"no rule files found in {directory}")
    return rules
