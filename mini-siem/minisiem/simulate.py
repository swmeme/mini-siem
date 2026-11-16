"""Synthetic log generator for the demo.

The generated scenario contains three independent incidents on a small web
shop infrastructure:

* SSH brute force against ``root`` from one address;
* SSH password spraying against several accounts from a second address;
* web vulnerability scanning and SQL injection attempts;
* a burst of application errors;
* a legitimate sudo command for context.

All addresses come from the RFC 5737 documentation ranges, so nothing points
at real hosts.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _syslog_time(moment: datetime) -> str:
    month = _MONTHS[moment.month - 1]
    return f"{month} {moment.day:02d} {moment:%H:%M:%S}"


def _http_time(moment: datetime) -> str:
    month = _MONTHS[moment.month - 1]
    return f"{moment.day:02d}/{month}/{moment.year}:{moment:%H:%M:%S} +0000"


def generate_demo_logs(
    directory: str | Path,
    base: datetime | None = None,
    seed: int = 7,
) -> dict[str, Path]:
    """Write ``auth.log``, ``access.log`` and ``app.jsonl`` into *directory*.

    Returns a mapping of source name to path, ready to be plugged into a
    :class:`~minisiem.config.Config`.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    base = (base or now - timedelta(minutes=20)).replace(second=0, microsecond=0)

    auth = _generate_auth(base, rng)
    web = _generate_web(base, rng)
    app = _generate_app(base)

    paths = {
        "auth": directory / "auth.log",
        "web": directory / "access.log",
        "app": directory / "app.jsonl",
    }
    paths["auth"].write_text("\n".join(auth) + "\n", encoding="utf-8")
    paths["web"].write_text("\n".join(web) + "\n", encoding="utf-8")
    paths["app"].write_text("\n".join(app) + "\n", encoding="utf-8")
    return paths


def _generate_auth(base: datetime, rng: random.Random) -> list[str]:
    lines: list[str] = []
    pid = 1000

    def add(offset: int, host: str, proc: str, message: str) -> None:
        nonlocal pid
        pid += rng.randint(1, 40)
        moment = base + timedelta(seconds=offset)
        lines.append(f"{_syslog_time(moment)} {host} {proc}[{pid}]: {message}")

    # Normal business activity.
    add(30, "web01", "sshd", "Accepted publickey for deploy from 10.0.0.18 port 52144 ssh2: RSA SHA256:9xK...")
    add(95, "web01", "sshd", "Accepted password for alice from 10.0.0.12 port 41022 ssh2")
    add(240, "web01", "sshd", "Accepted password for bob from 10.0.0.14 port 51190 ssh2")
    add(700, "db01", "sshd", "Accepted publickey for deploy from 10.0.0.18 port 52201 ssh2: RSA SHA256:9xK...")

    # Noise that the parser intentionally ignores.
    add(320, "web01", "CRON", "(root) CMD (run-parts /etc/cron.hourly)")
    add(900, "web01", "CRON", "(www-data) CMD (/usr/bin/php /var/www/shop/cron.php)")

    # Incident 1: brute force against root from 203.0.113.66.
    for index in range(12):
        add(
            180 + index * 7,
            "web01",
            "sshd",
            f"Failed password for root from 203.0.113.66 port {rng.randint(40000, 60000)} ssh2",
        )

    # Incident 2: password spraying from 198.51.100.23, one attempt per account.
    for index, user in enumerate(("admin", "test", "oracle", "postgres", "ubuntu", "hadoop", "jenkins", "backup")):
        add(
            420 + index * 18,
            "web01",
            "sshd",
            f"Failed password for invalid user {user} from 198.51.100.23 "
            f"port {rng.randint(40000, 60000)} ssh2",
        )

    # Context: a legitimate administrative action.
    add(760, "web01", "sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update")

    lines.sort(key=lambda line: line[:15])
    return lines


def _generate_web(base: datetime, rng: random.Random) -> list[str]:
    lines: list[str] = []
    normal_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0"

    def add(offset: int, ip: str, method: str, target: str, status: int, size: int, agent: str) -> None:
        moment = base + timedelta(seconds=offset)
        lines.append(
            f'{ip} - - [{_http_time(moment)}] "{method} {target} HTTP/1.1" '
            f'{status} {size} "-" "{agent}"'
        )

    # Normal storefront traffic.
    for index, (path, status, size) in enumerate((
        ("/", 200, 18422),
        ("/login", 200, 5120),
        ("/api/products?page=1", 200, 9021),
        ("/static/app.css", 200, 2210),
        ("/cart", 200, 4402),
        ("/api/orders", 201, 132),
        ("/favicon.ico", 304, 0),
        ("/products/42", 200, 7710),
    )):
        add(60 + index * 95, "10.0.0.20", "GET", path, status, size, normal_agent)

    # Incident 3: vulnerability scanner, 24 missing paths in under a minute.
    scan_paths = (
        "/admin", "/wp-login.php", "/.env", "/phpmyadmin/", "/backup.zip",
        "/config.php.bak", "/server-status", "/.git/config", "/xmlrpc.php",
        "/admin/config.php", "/db.sql", "/.aws/credentials",
    )
    for index in range(24):
        path = scan_paths[index % len(scan_paths)]
        add(110 + index * 2, "192.0.2.99", "GET", path, 404, 162, "sqlmap/1.7.2#stable")

    # Incident 4: SQL injection attempts against the product search.
    injections = (
        "/search?q=1%27+OR+%271%27%3D%271",
        "/product?id=1+UNION+SELECT+username,password+FROM+users",
        "/product?id=1%3B+WAITFOR+DELAY+%270%3A0%3A5%27",
        "/search?q=%27+AND+1%3D1+--",
    )
    for index, target in enumerate(injections):
        add(330 + index * 11, "192.0.2.44", "GET", target, 500 if index == 2 else 200, 774, "Mozilla/5.0")

    lines.sort(key=lambda line: line.split("[", 1)[1][:20])
    return lines


def _generate_app(base: datetime) -> list[str]:
    lines: list[str] = []

    def add(offset: int, level: str, service: str, message: str, **extra) -> None:
        moment = base + timedelta(seconds=offset)
        payload = {
            "ts": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": level,
            "service": service,
            "host": f"{service}-01",
            "msg": message,
            **extra,
        }
        lines.append(json.dumps(payload))

    add(20, "INFO", "api", "GET /health 200", user="-", ip="10.0.0.20")
    add(140, "INFO", "api", "POST /api/orders 201", user="alice", ip="10.0.0.12")
    add(200, "WARN", "billing", "payment gateway latency above 2s", user="alice", ip="10.0.0.12")

    # Incident 5: repeated database failures from the billing service.
    for index in range(12):
        add(
            540 + index * 3,
            "ERROR",
            "billing",
            "database connection timeout while reserving stock",
            user="-",
            ip="10.0.0.31",
            error="OperationalError",
            attempt=index + 1,
        )

    add(860, "INFO", "api", "GET /api/products?page=2 200", user="-", ip="10.0.0.20")
    add(880, "ERROR", "api", 'invalid JSON payload for /api/orders: {"qty": "two"}', user="bob", ip="10.0.0.14")

    lines.append("this line is deliberately not JSON and will be skipped")
    return lines
