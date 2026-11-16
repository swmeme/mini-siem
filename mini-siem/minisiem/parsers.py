"""Log parsers.

A parser turns one raw log line into one :class:`~minisiem.models.Event`, or
returns ``None`` when the line is not relevant (banners, cron noise, ...).
Parsers never raise on malformed input: robustness matters more than
completeness in a log pipeline.

Three formats are supported out of the box:

=========  ===============================  =====================
Parser     Input                            Typical file
=========  ===============================  =====================
``auth``   Linux auth.log / sshd + sudo     /var/log/auth.log
``web``    Apache / Nginx "combined" format access.log
``app``    JSON Lines application logs      app.jsonl
=========  ===============================  =====================
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, unquote_plus

from .models import Event

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


# ---------------------------------------------------------------------------
# Timestamp helpers (written by hand on purpose: strptime month names are
# locale dependent, and archived logs may be up to a year old).
# ---------------------------------------------------------------------------

def parse_syslog_time(text: str, now: datetime | None = None) -> datetime | None:
    """Parse ``Nov 16 10:12:33`` from a syslog line and infer the year."""
    match = re.match(r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", text.strip())
    if not match:
        return None
    month = _MONTHS.get(match.group(1).lower())
    if month is None:
        return None
    now = now or datetime.now(timezone.utc)
    for year in (now.year, now.year - 1):
        try:
            candidate = datetime(
                year, month, int(match.group(2)),
                int(match.group(3)), int(match.group(4)), int(match.group(5)),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
        # A log dated more than two days in the future belongs to last year.
        if candidate <= now + timedelta(days=2):
            return candidate
    return None


def parse_http_time(text: str) -> datetime | None:
    """Parse ``16/Nov/2026:10:12:33 +0000`` from an access log."""
    match = re.match(
        r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})",
        text.strip(),
    )
    if not match:
        return None
    month = _MONTHS.get(match.group(2).lower())
    if month is None:
        return None
    offset = timedelta(hours=int(match.group(8)), minutes=int(match.group(9)))
    if match.group(7) == "-":
        offset = -offset
    try:
        return datetime(
            int(match.group(3)), month, int(match.group(1)),
            int(match.group(4)), int(match.group(5)), int(match.group(6)),
            tzinfo=timezone(offset),
        )
    except ValueError:
        return None


def parse_iso_time(text: str) -> datetime | None:
    """Parse ISO-8601 timestamps, including the ``Z`` suffix."""
    value = text.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class Parser:
    """Base class for all parsers."""

    name = "base"
    dataset = "base"

    def parse(self, line: str) -> Event | None:  # pragma: no cover - interface
        raise NotImplementedError


# ---------------------------------------------------------------------------
# auth.log
# ---------------------------------------------------------------------------

_AUTH_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) "
    r"for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_SUDO = re.compile(
    r"^(?P<user>[\w.-]+)\s*:\s*.*?USER=(?P<target>[\w.-]+)\s*;\s*COMMAND=(?P<cmd>.*)"
)


class AuthParser(Parser):
    """Parse OpenSSH and sudo lines from a Linux authentication log."""

    name = "auth"
    dataset = "auth"

    def __init__(self, now: datetime | None = None) -> None:
        self.now = now

    def parse(self, line: str) -> Event | None:
        header = _AUTH_HEADER.match(line)
        if not header:
            return None
        timestamp = parse_syslog_time(header.group("ts"), self.now)
        if timestamp is None:
            return None

        host = header.group("host")
        proc = header.group("proc")
        message = header.group("msg").strip()
        base = {
            "event.dataset": self.dataset,
            "event.module": proc,
            "host.name": host,
            "process.name": proc,
            "message": message,
        }
        if header.group("pid"):
            base["process.pid"] = header.group("pid")

        match = _FAILED.search(message)
        if match:
            base.update({
                "event.action": "login_failed",
                "event.category": "authentication",
                "event.outcome": "failure",
                "auth.method": "password",
                "user.name": match.group("user"),
                "source.ip": match.group("ip"),
                "source.port": match.group("port"),
            })
            return Event(timestamp=timestamp, dataset=self.dataset, fields=base, raw=line.rstrip("\n"))

        match = _INVALID_USER.search(message)
        if match:
            base.update({
                "event.action": "login_failed",
                "event.category": "authentication",
                "event.outcome": "failure",
                "user.name": match.group("user"),
                "source.ip": match.group("ip"),
            })
            return Event(timestamp=timestamp, dataset=self.dataset, fields=base, raw=line.rstrip("\n"))

        match = _ACCEPTED.search(message)
        if match:
            base.update({
                "event.action": "login_success",
                "event.category": "authentication",
                "event.outcome": "success",
                "auth.method": match.group("method"),
                "user.name": match.group("user"),
                "source.ip": match.group("ip"),
                "source.port": match.group("port"),
            })
            return Event(timestamp=timestamp, dataset=self.dataset, fields=base, raw=line.rstrip("\n"))

        match = _SUDO.search(message)
        if match:
            base.update({
                "event.action": "sudo_command",
                "event.category": "process",
                "event.outcome": "success",
                "user.name": match.group("user"),
                "user.target.name": match.group("target"),
                "process.command_line": match.group("cmd").strip(),
            })
            return Event(timestamp=timestamp, dataset=self.dataset, fields=base, raw=line.rstrip("\n"))

        return None


# ---------------------------------------------------------------------------
# Web access logs (Apache/Nginx "combined")
# ---------------------------------------------------------------------------

_WEB = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>[^"\s]+)(?: [^"]*)?" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)


class WebParser(Parser):
    """Parse Apache/Nginx combined access logs."""

    name = "web"
    dataset = "web"

    def parse(self, line: str) -> Event | None:
        match = _WEB.match(line.rstrip("\n"))
        if not match:
            return None
        timestamp = parse_http_time(match.group("ts"))
        if timestamp is None:
            return None

        target = unquote(match.group("target"))
        path, _, query = target.partition("?")
        query = unquote_plus(query)
        status = match.group("status")
        size = match.group("size")
        fields = {
            "event.dataset": self.dataset,
            "event.action": "http_request",
            "event.category": "web",
            "event.outcome": "success" if status.startswith(("1", "2", "3")) else "failure",
            "source.ip": match.group("ip"),
            "http.request.method": match.group("method"),
            "url.original": target,
            "url.path": path,
            "http.response.status_code": status,
            "http.response.body.bytes": size if size.isdigit() else "0",
            "user_agent.original": match.group("agent") or "",
            "http.referrer": match.group("referrer") or "",
            "message": f'{match.group("method")} {target} -> {status}',
        }
        if query:
            fields["url.query"] = query
        return Event(timestamp=timestamp, dataset=self.dataset, fields=fields, raw=line.rstrip("\n"))


# ---------------------------------------------------------------------------
# Application logs (JSON Lines)
# ---------------------------------------------------------------------------

_APP_KEY_MAP = {
    "event": "event.action",
    "action": "event.action",
    "level": "log.level",
    "log.level": "log.level",
    "severity": "log.level",
    "user": "user.name",
    "username": "user.name",
    "user.name": "user.name",
    "ip": "source.ip",
    "src_ip": "source.ip",
    "source.ip": "source.ip",
    "service": "service.name",
    "service.name": "service.name",
    "msg": "message",
    "message": "message",
    "host": "host.name",
    "host.name": "host.name",
}


class AppParser(Parser):
    """Parse JSON Lines application logs (one JSON object per line)."""

    name = "app"
    dataset = "app"

    def parse(self, line: str) -> Event | None:
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        timestamp = parse_iso_time(str(payload.get("ts", payload.get("@timestamp", ""))))
        if timestamp is None:
            return None

        fields: dict[str, str] = {
            "event.dataset": self.dataset,
            "event.category": "application",
            "event.action": "log",
            "message": "",
        }
        for key, value in payload.items():
            if key in ("ts", "@timestamp") or value is None:
                continue
            if isinstance(value, (dict, list)):
                value = json.dumps(value, separators=(",", ":"))
            target = _APP_KEY_MAP.get(key, f"app.{key}")
            fields[target] = str(value)
            if target == "event.action":
                fields["event.action"] = str(value)
            if target == "log.level" and "event.outcome" not in fields:
                level = str(value).lower()
                fields["event.outcome"] = "failure" if level in ("error", "fatal", "critical") else "success"

        fields.setdefault("event.outcome", "success")
        return Event(timestamp=timestamp, dataset=self.dataset, fields=fields, raw=line.rstrip("\n"))


PARSERS: dict[str, type[Parser]] = {
    "auth": AuthParser,
    "web": WebParser,
    "app": AppParser,
}
