"""Configuration loading and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import SEVERITIES
from .parsers import PARSERS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.json"


class ConfigError(ValueError):
    """Raised when the configuration file is missing or invalid."""


@dataclass
class SourceConfig:
    name: str
    parser: str
    path: Path
    host: str | None = None


@dataclass
class Config:
    path: Path
    root: Path
    title: str = "Mini-SIEM Report"
    database: Path = field(default_factory=lambda: PROJECT_ROOT / "out" / "minisiem.db")
    rules_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "rules")
    report_path: Path = field(default_factory=lambda: PROJECT_ROOT / "out" / "report.html")
    sources: list[SourceConfig] = field(default_factory=list)
    console: bool = True
    min_severity: str = "low"
    cooldown_factor: float = 1.0

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
        if not config_path.is_file():
            raise ConfigError(f"configuration file not found: {config_path}")
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{config_path}: invalid JSON ({exc})") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{config_path}: top-level value must be a JSON object")

        root = config_path.resolve().parent

        def resolve(value: str, default: str) -> Path:
            return (root / (value or default)).resolve()

        raw_sources = data.get("sources")
        if not isinstance(raw_sources, list) or not raw_sources:
            raise ConfigError("'sources' must be a non-empty list")

        sources: list[SourceConfig] = []
        names: set[str] = set()
        for index, raw in enumerate(raw_sources):
            if not isinstance(raw, dict):
                raise ConfigError(f"source #{index + 1} must be an object")
            name, parser, raw_path = raw.get("name"), raw.get("parser"), raw.get("path")
            if not all(isinstance(value, str) and value for value in (name, parser, raw_path)):
                raise ConfigError(f"source #{index + 1} requires 'name', 'parser' and 'path'")
            if name in names:
                raise ConfigError(f"duplicate source name: {name!r}")
            if parser not in PARSERS:
                raise ConfigError(
                    f"source {name!r}: unknown parser {parser!r} "
                    f"(available: {', '.join(sorted(PARSERS))})"
                )
            names.add(name)
            host = raw.get("host")
            if host is not None and not isinstance(host, str):
                raise ConfigError(f"source {name!r}: 'host' must be a string")
            sources.append(SourceConfig(name=name, parser=parser, path=resolve(raw_path, ""), host=host))

        alerts = data.get("alerts", {})
        if not isinstance(alerts, dict):
            raise ConfigError("'alerts' must be an object")
        min_severity = alerts.get("min_severity", "low")
        if min_severity not in SEVERITIES:
            raise ConfigError(f"'alerts.min_severity' must be one of {', '.join(SEVERITIES)}")
        console = alerts.get("console", True)
        if not isinstance(console, bool):
            raise ConfigError("'alerts.console' must be true or false")

        engine = data.get("engine", {})
        if not isinstance(engine, dict):
            raise ConfigError("'engine' must be an object")
        cooldown_factor = engine.get("cooldown_factor", 1.0)
        if not isinstance(cooldown_factor, (int, float)) or isinstance(cooldown_factor, bool) or cooldown_factor <= 0:
            raise ConfigError("'engine.cooldown_factor' must be a number greater than zero")

        title = data.get("title", "Mini-SIEM Report")
        if not isinstance(title, str):
            raise ConfigError("'title' must be a string")

        return cls(
            path=config_path.resolve(),
            root=root,
            title=title,
            database=resolve(data.get("database", "out/minisiem.db"), "out/minisiem.db"),
            rules_dir=resolve(data.get("rules", "rules"), "rules"),
            report_path=resolve(data.get("report", "out/report.html"), "out/report.html"),
            sources=sources,
            console=console,
            min_severity=min_severity,
            cooldown_factor=float(cooldown_factor),
        )
