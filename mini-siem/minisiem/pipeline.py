"""The scan pipeline: collect -> parse -> normalize -> correlate -> alert."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import Config, SourceConfig
from .engine import DetectionEngine
from .models import Alert, Event
from .parsers import PARSERS, Parser
from .rules import Rule, load_rules


class PipelineError(RuntimeError):
    """Raised when a log source cannot be read."""


@dataclass
class SourceStats:
    name: str
    parser: str
    path: Path
    lines: int = 0
    parsed: int = 0
    skipped: int = 0

    @property
    def parse_rate(self) -> float:
        return (self.parsed / self.lines * 100.0) if self.lines else 0.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "parser": self.parser,
            "path": str(self.path),
            "lines": self.lines,
            "parsed": self.parsed,
            "skipped": self.skipped,
            "parse_rate": self.parse_rate,
        }


@dataclass
class ScanResult:
    events: list[Event]
    alerts: list[Alert]
    sources: list[SourceStats]
    rules: list[Rule]
    started: datetime
    finished: datetime
    unparsed: int = 0

    @property
    def duration_seconds(self) -> float:
        return (self.finished - self.started).total_seconds()

    @property
    def enabled_rules(self) -> int:
        return sum(1 for rule in self.rules if rule.enabled)


def _build_parser(name: str, now: datetime) -> Parser:
    if name == "auth":
        return PARSERS["auth"](now=now)
    return PARSERS[name]()


def collect_events(
    sources: list[SourceConfig], now: datetime
) -> tuple[list[Event], list[SourceStats], int]:
    """Read every configured source and return parsed events plus statistics."""
    events: list[Event] = []
    stats: list[SourceStats] = []
    errors = 0

    for source in sources:
        source_stats = SourceStats(name=source.name, parser=source.parser, path=source.path)
        stats.append(source_stats)
        parser = _build_parser(source.parser, now)
        try:
            handle = source.path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            raise PipelineError(f"cannot read source {source.name!r} at {source.path}: {exc}") from exc

        with handle:
            for raw_line in handle:
                line = raw_line.rstrip("\r\n")
                if not line.strip():
                    continue
                source_stats.lines += 1
                try:
                    event = parser.parse(line)
                except Exception:
                    # A parser bug must degrade to "skipped line", never abort a scan.
                    event = None
                    errors += 1
                if event is None:
                    source_stats.skipped += 1
                    continue
                if source.host:
                    event.fields.setdefault("host.name", source.host)
                event.fields.setdefault("event.source", source.name)
                events.append(event)
                source_stats.parsed += 1

    # Correlation windows need chronological order across all sources.
    events.sort(key=lambda event: (event.timestamp, event.dataset, event.id))
    return events, stats, errors


def run_scan(config: Config) -> ScanResult:
    """Execute the full pipeline described in the configuration."""
    started = datetime.now(timezone.utc)
    rules = load_rules(config.rules_dir)
    events, stats, errors = collect_events(config.sources, now=started)
    engine = DetectionEngine(rules, cooldown_factor=config.cooldown_factor)
    alerts = engine.process(events)
    alerts.sort(key=lambda alert: (alert.timestamp, alert.severity_score))
    finished = datetime.now(timezone.utc)
    return ScanResult(
        events=events,
        alerts=alerts,
        sources=stats,
        rules=rules,
        started=started,
        finished=finished,
        unparsed=sum(source.skipped for source in stats) + errors,
    )
