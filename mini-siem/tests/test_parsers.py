"""Tests for the log parsers."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from minisiem.parsers import AppParser, AuthParser, WebParser, parse_http_time, parse_syslog_time

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


class AuthParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = AuthParser(now=NOW)

    def test_failed_password(self) -> None:
        line = (
            "Nov 16 10:12:33 web01 sshd[1234]: Failed password for invalid user admin "
            "from 203.0.113.5 port 54321 ssh2"
        )
        event = self.parser.parse(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.dataset, "auth")
        self.assertEqual(event.timestamp, datetime(2026, 11, 16, 10, 12, 33, tzinfo=timezone.utc))
        self.assertEqual(event.get("event.action"), "login_failed")
        self.assertEqual(event.get("event.outcome"), "failure")
        self.assertEqual(event.get("user.name"), "admin")
        self.assertEqual(event.get("source.ip"), "203.0.113.5")
        self.assertEqual(event.get("source.port"), "54321")
        self.assertEqual(event.get("host.name"), "web01")

    def test_successful_publickey_login(self) -> None:
        line = (
            "Nov 16 10:15:00 web01 sshd[42]: Accepted publickey for deploy "
            "from 10.0.0.18 port 52144 ssh2: RSA SHA256:abc"
        )
        event = self.parser.parse(line)
        assert event is not None
        self.assertEqual(event.get("event.action"), "login_success")
        self.assertEqual(event.get("event.outcome"), "success")
        self.assertEqual(event.get("auth.method"), "publickey")
        self.assertEqual(event.get("user.name"), "deploy")

    def test_sudo_records_target_user_and_command(self) -> None:
        line = (
            "Nov 16 10:20:00 web01 sudo[900]: alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/usr/bin/apt-get update"
        )
        event = self.parser.parse(line)
        assert event is not None
        self.assertEqual(event.get("event.action"), "sudo_command")
        self.assertEqual(event.get("user.name"), "alice")
        self.assertEqual(event.get("user.target.name"), "root")
        self.assertEqual(event.get("process.command_line"), "/usr/bin/apt-get update")

    def test_invalid_user_line(self) -> None:
        line = "Nov 16 10:22:00 web01 sshd[91]: Invalid user oracle from 198.51.100.7"
        event = self.parser.parse(line)
        assert event is not None
        self.assertEqual(event.get("event.action"), "login_failed")
        self.assertEqual(event.get("user.name"), "oracle")

    def test_unrelated_syslog_line_is_ignored(self) -> None:
        line = "Nov 16 10:00:00 web01 CRON[77]: (root) CMD (run-parts /etc/cron.hourly)"
        self.assertIsNone(self.parser.parse(line))

    def test_year_rollover(self) -> None:
        january = datetime(2026, 1, 2, 0, 5, tzinfo=timezone.utc)
        self.assertEqual(
            parse_syslog_time("Dec 31 23:59:59", now=january),
            datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        )
        self.assertEqual(
            parse_syslog_time("Jan 01 00:01:00", now=january),
            datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        )


class WebParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = WebParser()

    def test_combined_log_line(self) -> None:
        line = (
            '203.0.113.5 - - [16/Nov/2026:10:12:33 +0000] "GET /admin.php HTTP/1.1" '
            '404 512 "-" "sqlmap/1.5"'
        )
        event = self.parser.parse(line)
        assert event is not None
        self.assertEqual(event.get("source.ip"), "203.0.113.5")
        self.assertEqual(event.get("http.request.method"), "GET")
        self.assertEqual(event.get("url.path"), "/admin.php")
        self.assertEqual(event.get("http.response.status_code"), "404")
        self.assertEqual(event.get("event.outcome"), "failure")
        self.assertEqual(event.get("user_agent.original"), "sqlmap/1.5")
        self.assertEqual(event.timestamp, datetime(2026, 11, 16, 10, 12, 33, tzinfo=timezone.utc))

    def test_query_is_url_decoded(self) -> None:
        line = (
            '192.0.2.44 - - [16/Nov/2026:10:15:00 +0000] '
            '"GET /product?id=1+UNION+SELECT+username+FROM+users HTTP/1.1" 200 774 "-" "Mozilla/5.0"'
        )
        event = self.parser.parse(line)
        assert event is not None
        self.assertEqual(event.get("url.path"), "/product")
        self.assertEqual(event.get("url.query"), "id=1 UNION SELECT username FROM users")

    def test_success_outcome(self) -> None:
        line = '10.0.0.20 - - [16/Nov/2026:10:15:00 +0000] "GET / HTTP/1.1" 304 0 "-" "Mozilla"'
        event = self.parser.parse(line)
        assert event is not None
        self.assertEqual(event.get("event.outcome"), "success")

    def test_malformed_line_is_ignored(self) -> None:
        self.assertIsNone(self.parser.parse("this is not an access log line"))

    def test_http_time_offset(self) -> None:
        parsed = parse_http_time("16/Nov/2026:10:12:33 -0300")
        assert parsed is not None
        self.assertEqual(parsed.utcoffset().total_seconds(), -3 * 3600)


class AppParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = AppParser()

    def test_json_line(self) -> None:
        line = (
            '{"ts":"2026-11-16T10:12:33Z","level":"ERROR","service":"billing",'
            '"user":"alice","ip":"10.0.0.12","msg":"payment failed","attempt":2}'
        )
        event = self.parser.parse(line)
        assert event is not None
        self.assertEqual(event.get("log.level"), "ERROR")
        self.assertEqual(event.get("event.outcome"), "failure")
        self.assertEqual(event.get("service.name"), "billing")
        self.assertEqual(event.get("user.name"), "alice")
        self.assertEqual(event.get("source.ip"), "10.0.0.12")
        self.assertEqual(event.get("message"), "payment failed")
        self.assertEqual(event.get("app.attempt"), "2")

    def test_invalid_json_is_ignored(self) -> None:
        self.assertIsNone(self.parser.parse("not json at all"))

    def test_missing_timestamp_is_ignored(self) -> None:
        self.assertIsNone(self.parser.parse('{"level":"INFO","msg":"hello"}'))


if __name__ == "__main__":
    unittest.main()
