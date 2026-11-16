"""Human-readable output: terminal summary and a self-contained HTML report."""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import SEVERITIES, SEVERITY_SCORE, Alert, Event, iso

_TIMELINE_STEPS = (60, 300, 600, 1800, 3600, 10800, 21600, 43200, 86400)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _badge(severity: str) -> str:
    return f'<span class="badge {severity}">{severity}</span>'


def summarize(events: list[Event], alerts: list[Alert]) -> dict:
    """Compute the aggregates used by both the console and the HTML report."""
    by_dataset = Counter(event.dataset for event in events)
    by_severity = Counter(alert.severity for alert in alerts)
    by_rule: Counter[str] = Counter()
    rule_titles: dict[str, str] = {}
    rule_severity: dict[str, str] = {}
    for alert in alerts:
        by_rule[alert.rule_id] += 1
        rule_titles[alert.rule_id] = alert.title
        if alert.severity_score > SEVERITY_SCORE.get(rule_severity.get(alert.rule_id, ""), 0):
            rule_severity[alert.rule_id] = alert.severity

    failures = Counter(
        event.get("source.ip")
        for event in events
        if event.get("event.outcome") == "failure" and event.get("source.ip")
    )

    return {
        "events": len(events),
        "alerts": len(alerts),
        "by_dataset": by_dataset,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "rule_titles": rule_titles,
        "rule_severity": rule_severity,
        "failed_by_ip": failures,
        "window": (events[0].timestamp, events[-1].timestamp) if events else None,
    }


def _timeline(alerts: list[Alert]) -> str:
    if not alerts:
        return '<p class="muted">No alerts were raised in this scan.</p>'

    first = min(alert.first_seen for alert in alerts)
    last = max(alert.last_seen for alert in alerts)
    span = max((last - first).total_seconds(), 1.0)
    step = next((value for value in _TIMELINE_STEPS if span / value <= 30), 86400)

    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    bins: Counter[int] = Counter()
    for alert in alerts:
        bins[int((alert.first_seen - epoch).total_seconds() // step)] += 1

    lowest, highest = min(bins), max(bins)
    peak = max(bins.values())
    rows = []
    for index in range(lowest, highest + 1):
        moment = datetime.fromtimestamp(index * step, tz=timezone.utc)
        label = moment.strftime("%d %b %H:%M") if step < 86400 else moment.strftime("%d %b")
        count = bins.get(index, 0)
        width = (count / peak * 100.0) if peak else 0.0
        rows.append(
            f'<div class="tl-row"><span class="tl-label">{_esc(label)}</span>'
            f'<span class="tl-track"><span class="tl-bar" style="width:{width:.1f}%"></span></span>'
            f'<span class="tl-count">{count}</span></div>'
        )
    return "".join(rows)


def _alert_rows(alerts: list[Alert]) -> str:
    ordered = sorted(alerts, key=lambda alert: (-alert.severity_score, -alert.last_seen.timestamp()))[:200]
    if not ordered:
        return '<tr><td colspan="6" class="muted">No alerts.</td></tr>'
    rows = []
    for alert in ordered:
        mitre = ", ".join(alert.mitre) if alert.mitre else "-"
        rows.append(
            "<tr>"
            f'<td>{_badge(alert.severity)}</td>'
            f'<td><strong>{_esc(alert.title)}</strong><br><span class="muted">{_esc(alert.rule_id)}</span></td>'
            f'<td class="mono">{_esc(alert.entity)}</td>'
            f'<td class="num">{alert.event_count}</td>'
            f'<td class="mono small">{_esc(iso(alert.first_seen))}<br>{_esc(iso(alert.last_seen))}</td>'
            f'<td class="mono small">{_esc(mitre)}</td>'
            "</tr>"
        )
    return "".join(rows)


def _dataset_rows(summary: dict) -> str:
    rows = []
    for dataset, count in summary["by_dataset"].most_common():
        rows.append(f'<tr><td class="mono">{_esc(dataset)}</td><td class="num">{count}</td></tr>')
    return "".join(rows) or '<tr><td colspan="2" class="muted">No events.</td></tr>'


def _ip_rows(summary: dict) -> str:
    rows = []
    for address, count in summary["failed_by_ip"].most_common(10):
        rows.append(f'<tr><td class="mono">{_esc(address)}</td><td class="num">{count}</td></tr>')
    return "".join(rows) or '<tr><td colspan="2" class="muted">No failures recorded.</td></tr>'


def _rule_rows(summary: dict) -> str:
    rows = []
    for rule_id, count in summary["by_rule"].most_common():
        rows.append(
            "<tr>"
            f'<td class="mono">{_esc(rule_id)}</td>'
            f"<td>{_esc(summary['rule_titles'].get(rule_id, ''))}</td>"
            f'<td>{_badge(summary["rule_severity"].get(rule_id, "informational"))}</td>'
            f'<td class="num">{count}</td>'
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="4" class="muted">No detections.</td></tr>'


def _meta_rows(meta: list[tuple[str, object]]) -> str:
    return "".join(
        f'<tr><th>{_esc(label)}</th><td class="mono">{_esc(value)}</td></tr>'
        for label, value in meta
    )


_CSS = """
:root {
  --ink: #111827;
  --muted: #6b7280;
  --line: #e5e7eb;
  --panel: #ffffff;
  --bg: #f6f7f9;
  --navy: #172554;
  --accent: #2563eb;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 40px 24px 64px;
  background: var(--bg); color: var(--ink);
  font: 15px/1.55 "Segoe UI", system-ui, -apple-system, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; }
header { border-bottom: 3px solid var(--navy); padding-bottom: 20px; margin-bottom: 28px; }
.eyebrow { margin: 0 0 6px; color: var(--accent); font-size: 12px; font-weight: 700;
  letter-spacing: .14em; text-transform: uppercase; }
h1 { margin: 0 0 8px; font-size: 32px; line-height: 1.15; }
h2 { margin: 0 0 14px; font-size: 17px; letter-spacing: .01em; }
.sub, .muted { color: var(--muted); }
.sub { margin: 0; font-size: 14px; }
section { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 22px 24px; margin-bottom: 20px; }
.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px;
  background: none; border: 0; padding: 0; }
.kpi { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 18px 20px; }
.kpi .value { display: block; font-size: 30px; font-weight: 700; line-height: 1.1; }
.kpi .label { display: block; margin-top: 6px; color: var(--muted); font-size: 12px;
  text-transform: uppercase; letter-spacing: .08em; }
.kpi.critical .value { color: #991b1b; }
.kpi.high .value { color: #c2410c; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
thead th { text-align: left; font-size: 11px; letter-spacing: .08em; text-transform: uppercase;
  color: var(--muted); border-bottom: 1px solid var(--line); padding: 8px 10px; }
tbody td { border-bottom: 1px solid var(--line); padding: 10px; vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.mono { font-family: "Cascadia Mono", Consolas, "SF Mono", monospace; font-size: 13px; }
.small { font-size: 12px; }
.badge { display: inline-block; min-width: 74px; padding: 2px 8px; border-radius: 999px;
  font-size: 11px; font-weight: 700; text-align: center; text-transform: uppercase;
  letter-spacing: .04em; }
.badge.informational { background: #f1f5f9; color: #475569; }
.badge.low { background: #e0f2fe; color: #075985; }
.badge.medium { background: #fef3c7; color: #92400e; }
.badge.high { background: #ffedd5; color: #9a3412; }
.badge.critical { background: #fee2e2; color: #991b1b; }
.tl-row { display: flex; align-items: center; gap: 12px; margin: 4px 0; }
.tl-label { flex: 0 0 118px; color: var(--muted); font-size: 12px; }
.tl-track { flex: 1; background: #eef2f7; border-radius: 4px; height: 14px; overflow: hidden; }
.tl-bar { display: block; height: 100%; background: var(--accent); border-radius: 4px; }
.tl-count { flex: 0 0 32px; text-align: right; font-size: 12px; font-variant-numeric: tabular-nums; }
.meta th { text-align: left; width: 150px; font-weight: 600; }
footer { color: var(--muted); font-size: 12px; text-align: center; margin-top: 28px; }
@media (max-width: 760px) {
  .kpis, .grid { grid-template-columns: 1fr; }
  body { padding: 24px 12px 40px; }
  section { padding: 18px; }
}
@media print {
  body { background: #fff; padding: 0; }
  section, .kpi { break-inside: avoid; box-shadow: none; }
}
"""


def build_report(
    *,
    title: str,
    events: list[Event],
    alerts: list[Alert],
    meta: list[tuple[str, object]] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render the complete, self-contained HTML report as a string."""
    generated_at = generated_at or datetime.now(timezone.utc)
    summary = summarize(events, alerts)
    window = summary["window"]
    window_text = f"{iso(window[0])} &rarr; {iso(window[1])}" if window else "no events"

    critical_high = summary["by_severity"].get("critical", 0) + summary["by_severity"].get("high", 0)
    failed_total = sum(summary["failed_by_ip"].values())

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <p class="eyebrow">Security log analysis</p>
    <h1>{_esc(title)}</h1>
    <p class="sub">Generated {_esc(iso(generated_at))} &middot; event window {window_text}</p>
  </header>

  <section class="kpis">
    <div class="kpi"><span class="value">{summary['events']}</span><span class="label">Events analyzed</span></div>
    <div class="kpi"><span class="value">{summary['alerts']}</span><span class="label">Alerts raised</span></div>
    <div class="kpi high"><span class="value">{critical_high}</span><span class="label">High / critical</span></div>
    <div class="kpi"><span class="value">{failed_total}</span><span class="label">Failed events with source IP</span></div>
  </section>

  <section>
    <h2>Alert timeline</h2>
    {_timeline(alerts)}
  </section>

  <section>
    <h2>Alerts</h2>
    <table>
      <thead><tr><th>Severity</th><th>Detection</th><th>Entity</th><th class="num">Events</th>
      <th>First / last seen</th><th>MITRE</th></tr></thead>
      <tbody>{_alert_rows(alerts)}</tbody>
    </table>
  </section>

  <div class="grid">
    <section>
      <h2>Events by source</h2>
      <table><thead><tr><th>Dataset</th><th class="num">Events</th></tr></thead>
      <tbody>{_dataset_rows(summary)}</tbody></table>
    </section>
    <section>
      <h2>Rules triggered</h2>
      <table><thead><tr><th>Rule</th><th>Title</th><th>Severity</th><th class="num">Alerts</th></tr></thead>
      <tbody>{_rule_rows(summary)}</tbody></table>
    </section>
  </div>

  <div class="grid">
    <section>
      <h2>Top source IPs &mdash; failed events</h2>
      <table><thead><tr><th>Source IP</th><th class="num">Failures</th></tr></thead>
      <tbody>{_ip_rows(summary)}</tbody></table>
    </section>
    <section>
      <h2>Scan metadata</h2>
      <table class="meta"><tbody>{_meta_rows(meta or [])}</tbody></table>
    </section>
  </div>

  <footer>Generated by Mini-SIEM v{__version__} &middot; normalized with an ECS-style field model</footer>
</div>
</body>
</html>
"""


def write_report(
    path: str | Path,
    *,
    title: str,
    events: list[Event],
    alerts: list[Alert],
    meta: list[tuple[str, object]] | None = None,
    generated_at: datetime | None = None,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_report(title=title, events=events, alerts=alerts, meta=meta, generated_at=generated_at),
        encoding="utf-8",
    )
    return path


def render_summary(
    *,
    events: list[Event],
    alerts: list[Alert],
    sources: list[dict] | None = None,
    rules_count: int | None = None,
    enabled_rules: int | None = None,
    duration_seconds: float | None = None,
    database: str | Path | None = None,
    report_path: str | Path | None = None,
    min_severity: str | None = None,
    show_alerts: bool = True,
    limit: int = 50,
) -> str:
    """Build the plain-text summary printed after a scan."""
    summary = summarize(events, alerts)
    lines: list[str] = ["Mini-SIEM scan summary", "=" * 21, f"Events analyzed : {summary['events']}"]

    for source in sources or []:
        lines.append(
            f"  {source['name']:<12} {source['lines']:>5} lines | "
            f"{source['parsed']:>5} parsed | {source['parse_rate']:>5.1f}%"
        )

    if summary["window"]:
        first, last = summary["window"]
        lines.append(f"Window          : {iso(first)} -> {iso(last)}")
    if rules_count is not None:
        suffix = f" ({enabled_rules} enabled)" if enabled_rules is not None else ""
        lines.append(f"Rules evaluated : {rules_count}{suffix}")
    lines.append(f"Alerts raised   : {summary['alerts']}")

    severities = " | ".join(
        f"{severity} {summary['by_severity'].get(severity, 0)}"
        for severity in reversed(SEVERITIES)
        if summary["by_severity"].get(severity, 0) or severity in ("high", "medium", "low", "critical")
    )
    if severities:
        lines.append(f"  Severity      : {severities}")
    if duration_seconds is not None:
        lines.append(f"Duration        : {duration_seconds:.2f} s")
    if database:
        lines.append(f"Database        : {database}")
    if report_path:
        lines.append(f"Report          : {report_path}")

    threshold = min_severity or "informational"
    minimum = SEVERITY_SCORE.get(threshold, 0)
    visible = [alert for alert in alerts if alert.severity_score >= minimum]
    hidden = len(alerts) - len(visible)
    if alerts and show_alerts:
        lines.extend(["", f"Alerts (console threshold: {threshold})", "-" * 34])
        ordered = sorted(visible, key=lambda alert: (-alert.severity_score, -alert.last_seen.timestamp()))
        for alert in ordered[:limit]:
            entity = alert.entity if len(alert.entity) <= 52 else alert.entity[:49] + "..."
            lines.append(
                f"[{alert.severity:<13}] {iso(alert.timestamp)}  "
                f"{alert.rule_id:<26} {alert.event_count:>3} events  {entity}"
            )
        if len(visible) > limit:
            lines.append(f"... and {len(visible) - limit} more alerts")
        if hidden:
            lines.append(f"({hidden} alert(s) below the console threshold)")
    return "\n".join(lines)
