"""Tests for rule loading, matching and the correlation engine."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from minisiem.engine import DetectionEngine
from minisiem.models import Event
from minisiem.rules import Rule, RuleError, load_rules

BASE = datetime(2026, 11, 16, 10, 0, tzinfo=timezone.utc)


def make_event(seconds: int, **fields: str) -> Event:
    defaults = {
        "event.action": "login_failed",
        "event.outcome": "failure",
        "user.name": "root",
        "source.ip": "203.0.113.66",
    }
    defaults.update(fields)
    return Event(
        timestamp=BASE + timedelta(seconds=seconds),
        dataset=fields.get("event.dataset", "auth"),
        fields=defaults,
        raw="test",
    )


def brute_force_rule() -> Rule:
    return Rule(
        id="TEST-BRUTE",
        title="Test brute force",
        severity="high",
        dataset="auth",
        match={"event.action": "login_failed"},
        group_by=["source.ip", "user.name"],
        count=5,
        window_seconds=120,
    )


class RuleMatchingTests(unittest.TestCase):
    def test_condition_types(self) -> None:
        rule = Rule(
            id="TEST-MATCH",
            title="Matching",
            dataset="web",
            match={
                "http.response.status_code": ["404", "403"],
                "url.query": {"regex": r"union\s+select"},
                "source.ip": {"not": "10.0.0.1"},
            },
        )
        event = make_event(
            0,
            **{
                "event.dataset": "web",
                "http.response.status_code": "404",
                "url.query": "id=1 UNION SELECT password",
                "source.ip": "192.0.2.44",
            },
        )
        self.assertTrue(rule.matches(event))

        event.fields["url.query"] = "id=1"
        self.assertFalse(rule.matches(event))

        event.fields["url.query"] = "id=1 UNION SELECT password"
        event.fields["source.ip"] = "10.0.0.1"
        self.assertFalse(rule.matches(event))

    def test_missing_field_does_not_match(self) -> None:
        rule = Rule(id="TEST", title="Test", match={"user.name": "root"})
        self.assertFalse(rule.matches(make_event(0, **{"user.name": ""})))

    def test_validation_rejects_bad_rules(self) -> None:
        invalid = [
            {"title": "no id"},
            {"id": "X", "title": "bad severity", "severity": "urgent", "match": {"a": "b"}},
            {"id": "X", "title": "no match"},
            {"id": "X", "title": "bad regex", "match": {"a": {"regex": "("}}},
            {
                "id": "X",
                "title": "threshold without group",
                "match": {"a": "b"},
                "threshold": {"count": 5, "window_seconds": 60},
            },
            {
                "id": "X",
                "title": "threshold without window",
                "match": {"a": "b"},
                "group_by": ["a"],
                "threshold": {"count": 5},
            },
        ]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(RuleError):
                Rule.from_dict(data)

    def test_duplicate_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = {"id": "DUP", "title": "x", "match": {"a": "b"}}
            for name in ("one.json", "two.json"):
                Path(directory, name).write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(RuleError):
                load_rules(directory)


class EngineTests(unittest.TestCase):
    def test_threshold_fires_once_then_cools_down(self) -> None:
        events = [make_event(index, **{"source.port": str(index)}) for index in range(10)]
        alerts = DetectionEngine([brute_force_rule()]).process(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "TEST-BRUTE")
        self.assertEqual(alert.event_count, 5)
        self.assertEqual(alert.entity, "source.ip=203.0.113.66, user.name=root")
        self.assertEqual(len(alert.event_ids), 5)

    def test_events_outside_window_do_not_trigger(self) -> None:
        events = [make_event(index * 40) for index in range(5)]
        self.assertEqual(DetectionEngine([brute_force_rule()]).process(events), [])

    def test_grouping_separates_entities(self) -> None:
        events = []
        for index in range(4):
            events.append(make_event(index, **{"source.ip": "198.51.100.1"}))
            events.append(make_event(index + 1, **{"source.ip": "198.51.100.2"}))
        self.assertEqual(DetectionEngine([brute_force_rule()]).process(events), [])

    def test_distinct_users_detects_spray(self) -> None:
        rule = Rule(
            id="TEST-SPRAY",
            title="Spray",
            dataset="auth",
            match={"event.action": "login_failed"},
            group_by=["source.ip"],
            count=5,
            window_seconds=300,
            distinct_by="user.name",
        )
        users = ("admin", "test", "oracle", "postgres", "ubuntu")
        events = [make_event(index * 5, **{"user.name": user}) for index, user in enumerate(users)]
        alerts = DetectionEngine([rule]).process(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 5)

    def test_distinct_does_not_fire_for_single_account(self) -> None:
        rule = Rule(
            id="TEST-SPRAY",
            title="Spray",
            dataset="auth",
            match={"event.action": "login_failed"},
            group_by=["source.ip"],
            count=5,
            window_seconds=300,
            distinct_by="user.name",
        )
        events = [make_event(index) for index in range(10)]
        self.assertEqual(DetectionEngine([rule]).process(events), [])

    def test_single_event_rule_emits_each_event(self) -> None:
        rule = Rule(
            id="TEST-SINGLE",
            title="Single",
            dataset="auth",
            match={"event.action": "sudo_command"},
        )
        events = [
            make_event(0, **{"event.action": "sudo_command"}),
            make_event(10, **{"event.action": "sudo_command"}),
        ]
        self.assertEqual(len(DetectionEngine([rule]).process(events)), 2)

    def test_disabled_rules_are_skipped(self) -> None:
        rule = brute_force_rule()
        rule.enabled = False
        events = [make_event(index) for index in range(10)]
        self.assertEqual(DetectionEngine([rule]).process(events), [])

    def test_cooldown_can_be_scaled(self) -> None:
        events = [make_event(index) for index in range(10)]
        events += [make_event(60 + index) for index in range(5)]
        default = DetectionEngine([brute_force_rule()]).process(events)
        relaxed = DetectionEngine([brute_force_rule()], cooldown_factor=0.5).process(events)
        self.assertEqual(len(default), 1)
        self.assertEqual(len(relaxed), 2)


if __name__ == "__main__":
    unittest.main()
