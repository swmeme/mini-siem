"""End-to-end tests: configuration, pipeline, storage, report and CLI."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from minisiem.cli import main
from minisiem.config import Config, ConfigError
from minisiem.models import Alert, Event
from minisiem.pipeline import run_scan
from minisiem.report import build_report, write_report
from minisiem.simulate import generate_demo_logs
from minisiem.storage import Storage

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"


def write_config(directory: Path, logs: dict[str, Path] | None = None, **overrides) -> Path:
    if logs is None:
        logs = generate_demo_logs(directory / "logs")
    payload = {
        "title": "Test report",
        "database": "out/test.db",
        "rules": str(RULES_DIR),
        "report": "out/report.html",
        "sources": [
            {"name": "auth", "parser": "auth", "path": str(logs["auth"])},
            {"name": "web", "parser": "web", "path": str(logs["web"]), "host": "web01"},
            {"name": "app", "parser": "app", "path": str(logs["app"])},
        ],
        "alerts": {"console": True, "min_severity": "low"},
    }
    payload.update(overrides)
    path = directory / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class PipelineTests(unittest.TestCase):
    def test_demo_scenario_detects_all_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Config.load(write_config(Path(directory)))
            result = run_scan(config)

            self.assertEqual(len(result.events), 78)
            self.assertEqual(
                {alert.rule_id for alert in result.alerts},
                {
                    "SSH-BRUTEFORCE-001",
                    "SSH-PASSWORD-SPRAY-002",
                    "WEB-DIRECTORY-SCAN-003",
                    "WEB-SQL-INJECTION-004",
                    "PRIV-SUDO-ROOT-005",
                    "APP-ERROR-BURST-006",
                },
            )
            self.assertEqual(result.enabled_rules, 6)
            self.assertGreaterEqual(result.unparsed, 2)
            # Events must be globally ordered for the sliding windows to work.
            timestamps = [event.timestamp for event in result.events]
            self.assertEqual(timestamps, sorted(timestamps))
            # The source host is applied when the log format does not carry it.
            web_event = next(event for event in result.events if event.dataset == "web")
            self.assertEqual(web_event.get("host.name"), "web01")

    def test_storage_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Config.load(write_config(Path(directory)))
            result = run_scan(config)
            with Storage(config.database) as storage:
                storage.write(result.events, result.alerts, reset=True)
                events = storage.load_events()
                alerts = storage.load_alerts()
                counts = storage.counts()
            self.assertEqual(counts, (len(result.events), len(result.alerts)))
            self.assertEqual(len(events), len(result.events))
            self.assertEqual(len(alerts), len(result.alerts))
            self.assertEqual(events[0].timestamp, result.events[0].timestamp)
            self.assertEqual(events[0].fields, result.events[0].fields)
            by_rule = {alert.rule_id: alert for alert in alerts}
            self.assertEqual(by_rule["SSH-BRUTEFORCE-001"].event_count, 5)
            self.assertIn("source.ip=203.0.113.66", by_rule["SSH-BRUTEFORCE-001"].entity)

    def test_report_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Config.load(write_config(Path(directory)))
            result = run_scan(config)
            path = write_report(
                config.report_path,
                title=config.title,
                events=result.events,
                alerts=result.alerts,
                meta=[("Rules", 6)],
            )
            content = path.read_text(encoding="utf-8")
            self.assertIn("Test report", content)
            self.assertIn("WEB-SQL-INJECTION-004", content)
            self.assertIn("Alert timeline", content)

    def test_report_escapes_untrusted_fields(self) -> None:
        moment = datetime(2026, 11, 16, 10, 0, tzinfo=timezone.utc)
        event = Event(
            timestamp=moment,
            dataset="web",
            fields={"url.path": "<script>alert(1)</script>", "source.ip": "<b>1.2.3.4</b>"},
        )
        alert = Alert(
            rule_id="TEST-XSS",
            title="<script>bad</script>",
            severity="high",
            timestamp=moment,
            entity='"><script>alert(2)</script>',
            event_count=1,
            first_seen=moment,
            last_seen=moment,
        )
        content = build_report(title="<script>alert(0)</script>", events=[event], alerts=[alert])
        self.assertNotIn("<script>alert", content)
        self.assertIn("&lt;script&gt;", content)

    def test_cli_run_and_fail_on(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = write_config(Path(directory))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(["run", "-c", str(config_path), "--no-db", "--no-report"])
            self.assertEqual(code, 0)
            self.assertIn("Alerts raised", output.getvalue())

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(["run", "-c", str(config_path), "--no-db", "--no-report", "--fail-on", "critical"])
            self.assertEqual(code, 2)

    def test_cli_report_requires_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = write_config(Path(directory))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["report", "-c", str(config_path)]), 1)


class ConfigTests(unittest.TestCase):
    def test_invalid_parser_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_config(
                Path(directory),
                sources=[{"name": "x", "parser": "nope", "path": "x.log"}],
            )
            with self.assertRaises(ConfigError):
                Config.load(path)

    def test_relative_paths_are_resolved_from_config_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_config(Path(directory))
            config = Config.load(path)
            self.assertEqual(config.database, Path(directory).resolve() / "out" / "test.db")
            self.assertTrue(config.rules_dir.is_absolute())

    def test_missing_sources_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_config(Path(directory), sources=[])
            with self.assertRaises(ConfigError):
                Config.load(path)


if __name__ == "__main__":
    unittest.main()
