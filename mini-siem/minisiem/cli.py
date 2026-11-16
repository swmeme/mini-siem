"""Command line interface: ``python -m minisiem --help``."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, SourceConfig
from .models import SEVERITIES, SEVERITY_SCORE
from .pipeline import PipelineError, ScanResult, run_scan
from .report import render_summary, write_report
from .rules import RuleError, load_rules
from .simulate import generate_demo_logs
from .storage import Storage

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2


def _exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    threshold = SEVERITY_SCORE[fail_on]
    if any(alert.severity_score >= threshold for alert in result.alerts):
        print(
            f"\nFail-on threshold reached: at least one alert is {fail_on} or above.",
            file=sys.stderr,
        )
        return EXIT_THRESHOLD
    return EXIT_OK


def _persist_and_report(
    config: Config,
    result: ScanResult,
    *,
    no_db: bool = False,
    no_report: bool = False,
    fail_on: str = "none",
    extra_meta: list[tuple[str, object]] | None = None,
) -> int:
    database: Path | None = None
    if not no_db:
        with Storage(config.database) as storage:
            storage.write(result.events, result.alerts, reset=True)
        database = config.database

    meta: list[tuple[str, object]] = [
        ("Configuration", config.path),
        ("Sources", ", ".join(source.name for source in result.sources)),
        ("Rules", f"{len(result.rules)} loaded, {result.enabled_rules} enabled"),
        ("Duration", f"{result.duration_seconds:.2f} s"),
        ("Database", database or "not persisted"),
    ]
    meta.extend(extra_meta or [])

    report_path: Path | None = None
    if not no_report:
        report_path = write_report(
            config.report_path,
            title=config.title,
            events=result.events,
            alerts=result.alerts,
            meta=meta,
        )

    print(render_summary(
        events=result.events,
        alerts=result.alerts,
        sources=[source.as_dict() for source in result.sources],
        rules_count=len(result.rules),
        enabled_rules=result.enabled_rules,
        duration_seconds=result.duration_seconds,
        database=database,
        report_path=report_path,
        min_severity=config.min_severity,
        show_alerts=config.console,
    ))
    return _exit_code(result, fail_on)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    result = run_scan(config)
    return _persist_and_report(
        config,
        result,
        no_db=args.no_db,
        no_report=args.no_report,
        fail_on=args.fail_on,
    )


def cmd_demo(args: argparse.Namespace) -> int:
    base_config = Config.load(args.config)
    output = Path(args.out).expanduser().resolve()
    logs = generate_demo_logs(output / "logs")
    config = replace(
        base_config,
        title="Mini-SIEM Demo Report",
        sources=[
            SourceConfig(name="auth", parser="auth", path=logs["auth"]),
            SourceConfig(name="web", parser="web", path=logs["web"]),
            SourceConfig(name="app", parser="app", path=logs["app"]),
        ],
        database=output / "minisiem.db",
        report_path=output / "report.html",
    )
    print(f"Demo logs written to {output / 'logs'}")
    result = run_scan(config)
    return _persist_and_report(
        config,
        result,
        fail_on=args.fail_on,
        extra_meta=[("Logs", output / "logs")],
    )


def cmd_report(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    if not config.database.is_file():
        print(
            f"error: database not found: {config.database}\n"
            "Run 'python -m minisiem run' first.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    with Storage(config.database) as storage:
        events = storage.load_events()
        alerts = storage.load_alerts()

    destination = Path(args.out).expanduser().resolve() if args.out else config.report_path
    path = write_report(
        destination,
        title=config.title,
        events=events,
        alerts=alerts,
        meta=[
            ("Database", config.database),
            ("Events", len(events)),
            ("Alerts", len(alerts)),
        ],
    )
    print(render_summary(
        events=events,
        alerts=alerts,
        database=config.database,
        report_path=path,
        min_severity=config.min_severity,
        show_alerts=False,
    ))
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    rules = load_rules(config.rules_dir)
    print(f"Rules directory: {config.rules_dir}\n")
    print(f"{'ID':<28} {'SEVERITY':<14} {'TYPE':<40} TITLE")
    print("-" * 118)
    for rule in rules:
        state = "" if rule.enabled else "  [disabled]"
        print(f"{rule.id:<28} {rule.severity:<14} {rule.kind:<40} {rule.title}{state}")
    print(f"\n{len(rules)} rule(s), {sum(rule.enabled for rule in rules)} enabled")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minisiem",
        description="Mini-SIEM: parse security logs, correlate events and raise alerts.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="analyze the configured log sources")
    run.add_argument("-c", "--config", help="path to config.json (default: project config)")
    run.add_argument("--no-db", action="store_true", help="do not persist events and alerts")
    run.add_argument("--no-report", action="store_true", help="do not write the HTML report")
    run.add_argument(
        "--fail-on",
        choices=("none", *SEVERITIES),
        default="none",
        help="exit with code 2 when an alert reaches this severity",
    )
    run.set_defaults(func=cmd_run)

    demo = commands.add_parser("demo", help="generate synthetic logs and run a full scan")
    demo.add_argument("-c", "--config", help="configuration whose rules should be used")
    demo.add_argument("--out", default="out/demo", help="output directory (default: out/demo)")
    demo.add_argument(
        "--fail-on",
        choices=("none", *SEVERITIES),
        default="none",
        help="exit with code 2 when an alert reaches this severity",
    )
    demo.set_defaults(func=cmd_demo)

    report = commands.add_parser("report", help="rebuild the HTML report from the database")
    report.add_argument("-c", "--config", help="path to config.json")
    report.add_argument("--out", help="destination HTML file")
    report.set_defaults(func=cmd_report)

    rules = commands.add_parser("rules", help="list the loaded detection rules")
    rules.add_argument("-c", "--config", help="path to config.json")
    rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ConfigError, RuleError, PipelineError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
