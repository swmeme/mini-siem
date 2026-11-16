# Mini-SIEM

A small but complete **Security Information and Event Management (SIEM)** pipeline written in pure Python, with no third-party dependencies. It collects Linux authentication logs, web server access logs and JSON application logs, normalizes them into a common schema, correlates them with sliding-window detection rules, stores the results in SQLite and produces a self-contained HTML incident report.

It was built as a university project, but every component is real: there is a parser layer, a rule engine, stateful correlation, persistence, tests and a CLI.

```text
python -m minisiem demo     # generate a realistic incident scenario and analyze it
```

---

## What is a SIEM?

A **SIEM** is the part of a security operations center that turns raw logs into decisions. Commercial SIEMs (Splunk, Microsoft Sentinel, Elastic Security, IBM QRadar, Wazuh) are large platforms, but conceptually they all implement the same five stages:

| Stage | Question it answers | Typical implementation |
|---|---|---|
| **Collection** | Where do the logs come from? | Agents, syslog forwarders, APIs |
| **Parsing & normalization** | What happened, in a common vocabulary? | Field extraction, ECS/OCSF schemas |
| **Correlation & detection** | Does this pattern mean something? | Rules, thresholds, anomaly models |
| **Alerting** | Who needs to know, and how urgently? | Tickets, e-mail, chat, SOAR playbooks |
| **Retention & reporting** | What is the evidence? | Indexed storage, dashboards, audits |

### What is a *mini*-SIEM?

A **mini-SIEM** is a deliberately small implementation of that pipeline. It keeps the architecture and the analyst workflow, but trades scale for clarity:

* it reads files instead of managing agents and clusters;
* it evaluates a handful of understandable rules instead of machine-learning models;
* it runs as a batch process instead of a 24/7 distributed service;
* it stores data in a single SQLite file instead of a distributed index.

The goal is **not** to replace a production SIEM. The goal is to show, end to end and in code you can read in an afternoon, how detection engineering actually works: normalization, correlation windows, severity, false positives, tuning and evidence.

---

## Features

* **3 log parsers** — Linux `auth.log` (sshd + sudo), Apache/Nginx *combined* access logs and JSON Lines application logs.
* **ECS-style normalization** — dotted field names such as `source.ip`, `event.action`, `user.name`, `url.query`.
* **Stateful correlation engine** — sliding time windows, grouping keys, cooldowns and *distinct-value* counting (which separates brute force from password spraying).
* **6 detection rules** mapped to MITRE ATT&CK, defined in readable JSON.
* **SQLite persistence** with indexed columns for the fields analysts filter on.
* **Self-contained HTML report** — KPIs, alert timeline, alert table, top source IPs, rules triggered.
* **Synthetic demo** — five incidents (brute force, spraying, scanning, SQL injection, error burst) generated on demand using RFC 5737 documentation addresses.
* **35 automated tests**, standard library only.
* **CI-friendly CLI** — `--fail-on high` exits with code 2 when a serious alert is raised.

---

## Quick start

Requirements: **Python 3.10+**. No `pip install` needed.

```bash
cd mini-siem

python -m minisiem demo        # generate logs + scan + report
python -m minisiem run         # scan the samples in config.json
python -m minisiem rules       # list the detection rules
python -m minisiem report      # rebuild the HTML report from SQLite
```

Open `out/demo/report.html` in a browser.

### Expected output

```text
Mini-SIEM scan summary
=====================
Events analyzed : 78
  auth            27 lines |    25 parsed |  92.6%
  web             36 lines |    36 parsed | 100.0%
  app             18 lines |    17 parsed |  94.4%
Window          : 2026-11-16T20:16:20Z -> 2026-11-16T20:30:40Z
Rules evaluated : 6 (6 enabled)
Alerts raised   : 6
  Severity      : critical 1 | high 2 | medium 2 | low 1
Duration        : 0.01 s
Database        : .../out/demo/minisiem.db
Report          : .../out/demo/report.html

Alerts (console threshold: low)
----------------------------------
[critical     ] 2026-11-16T20:21:30Z  WEB-SQL-INJECTION-004        1 events  source.ip=192.0.2.44
[high         ] 2026-11-16T20:24:12Z  SSH-PASSWORD-SPRAY-002       5 events  source.ip=198.51.100.23
[high         ] 2026-11-16T20:19:28Z  SSH-BRUTEFORCE-001           5 events  source.ip=203.0.113.66, user.name=root
[medium       ] 2026-11-16T20:25:27Z  APP-ERROR-BURST-006         10 events  service.name=billing
[medium       ] 2026-11-16T20:18:28Z  WEB-DIRECTORY-SCAN-003      20 events  source.ip=192.0.2.99
[low          ] 2026-11-16T20:28:40Z  PRIV-SUDO-ROOT-005           1 events  user.name=alice
```

The numbers are deterministic except for timestamps: the demo places the scenario 20 minutes before the current time.

---

## How it works

```text
samples/auth.log ----\
samples/access.log ---+--> Parsers --> Normalized events --> Detection engine --> Alerts
samples/app.jsonl ----/    auth/web/app   (ECS-style, UTC)     (sliding windows)      |
                                                                                      +--> SQLite  (out/minisiem.db)
                                                                                      +--> HTML    (out/report.html)
```

### 1. Collection

`minisiem/config.json` maps each source to a parser and a file:

```json
{
  "sources": [
    { "name": "auth", "parser": "auth", "path": "samples/auth.log" },
    { "name": "web",  "parser": "web",  "path": "samples/access.log", "host": "web01" },
    { "name": "app",  "parser": "app",  "path": "samples/app.jsonl" }
  ]
}
```

Paths are resolved relative to the configuration file, so the project can be moved without edits.

### 2. Parsing and normalization

Each parser turns one line into one event. Lines that are irrelevant (cron noise, banners) or malformed are counted and skipped — a bad line never stops a scan.

A failed SSH login becomes:

```json
{
  "timestamp": "2026-11-16T09:43:21Z",
  "dataset": "auth",
  "fields": {
    "event.dataset": "auth",
    "event.action": "login_failed",
    "event.category": "authentication",
    "event.outcome": "failure",
    "auth.method": "password",
    "user.name": "root",
    "source.ip": "203.0.113.66",
    "source.port": "51804",
    "host.name": "web01",
    "process.name": "sshd",
    "message": "Failed password for root from 203.0.113.66 port 51804 ssh2"
  }
}
```

The field model follows the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) where it makes sense. Flattening the names (`source.ip` instead of nested objects) keeps matching and rule files trivial.

**Why normalize at all?** Because detection should not care whether the IP came from sshd, Nginx or a JSON field called `ip`. Normalization is what makes one rule reusable across sources — the central idea of a SIEM.

### 3. Correlation and detection

Events from all sources are merged and sorted chronologically. The engine keeps a `deque` per `(rule, grouping key)` and applies:

1. **match** — field conditions (exact value, list of values, regex, negation);
2. **group** — e.g. per `source.ip`, or per `(source.ip, user.name)`;
3. **window** — events older than `window_seconds` are evicted;
4. **threshold** — `count` events, or `count` *distinct* values of a field;
5. **cooldown** — while an incident is ongoing, do not emit one alert per event.

That is the entire state machine. No message queue, no daemon, no hidden magic.

### 4. Alerting, storage and reporting

Alerts carry severity, entity, first/last seen timestamps, the last 20 event IDs, tags and MITRE technique IDs. They are printed, inserted into SQLite and rendered into an HTML report that can be attached to a university submission or an incident ticket.

---

## Detection rules

Rules are JSON files in `rules/`. A threshold rule:

```json
{
  "id": "SSH-BRUTEFORCE-001",
  "title": "SSH brute force against a single account",
  "description": "Five or more failed SSH passwords for the same account and source within two minutes.",
  "severity": "high",
  "dataset": "auth",
  "match": { "event.action": "login_failed" },
  "group_by": ["source.ip", "user.name"],
  "threshold": { "count": 5, "window_seconds": 120 },
  "tags": ["authentication", "brute-force"],
  "mitre": ["T1110.001"]
}
```

A rule that detects spraying counts **distinct users** instead of events:

```json
{
  "id": "SSH-PASSWORD-SPRAY-002",
  "match": { "event.action": "login_failed" },
  "group_by": ["source.ip"],
  "threshold": { "count": 5, "window_seconds": 300, "distinct_by": "user.name" }
}
```

This distinction matters: an attacker guessing one password many times is brute force; an attacker guessing a few passwords across many accounts is spraying. The events look similar, the response is different.

Shipped rules:

| Rule ID | Detects | Severity | ATT&CK |
|---|---|---|---|
| `SSH-BRUTEFORCE-001` | ≥5 failures per account/IP in 120 s | high | T1110.001 |
| `SSH-PASSWORD-SPRAY-002` | ≥5 distinct users per IP in 300 s | high | T1110.003 |
| `WEB-DIRECTORY-SCAN-003` | ≥20 HTTP 404 per IP in 60 s | medium | T1595.002 |
| `WEB-SQL-INJECTION-004` | SQLi idioms in the query string | critical | T1190 |
| `PRIV-SUDO-ROOT-005` | sudo executed as root | low | T1548.003 |
| `APP-ERROR-BURST-006` | ≥10 ERROR logs per service in 60 s | medium | — |

The full schema, semantics and tuning guide are in [docs/RULES.md](docs/RULES.md).

---

## CLI

| Command | Purpose |
|---|---|
| `python -m minisiem run` | Analyze configured sources, persist and report |
| `python -m minisiem demo` | Generate synthetic logs and run the full pipeline |
| `python -m minisiem rules` | List loaded rules, their type and severity |
| `python -m minisiem report` | Rebuild the HTML report from the SQLite database |

Useful flags:

```bash
python -m minisiem run -c my-config.json      # alternate configuration
python -m minisiem run --no-db --no-report    # dry run
python -m minisiem run --fail-on high         # exit 2 if a high/critical alert exists
```

`--fail-on` makes the tool usable as a CI gate: a test environment can fail a build when a critical detection appears in its logs.

---

## Project layout

```text
mini-siem/
├── config.json              # sources, paths, console threshold
├── rules/                   # one JSON file per detection
├── samples/                 # small static logs for `run`
├── minisiem/
│   ├── models.py            # Event and Alert data classes
│   ├── parsers.py           # auth / web / JSON parsers
│   ├── rules.py             # rule schema, validation, loading
│   ├── engine.py            # sliding-window correlation
│   ├── config.py            # configuration loading
│   ├── pipeline.py          # collect -> parse -> correlate
│   ├── storage.py           # SQLite persistence
│   ├── report.py            # HTML report and console summary
│   ├── simulate.py          # synthetic incident generator
│   └── cli.py               # argparse entry point
├── tests/                   # 35 unittest cases
├── docs/
│   ├── ARCHITECTURE.md      # design, data model, algorithms
│   ├── RULES.md             # rule reference and tuning guide
│   ├── REPORT.md            # academic write-up
│   └── DEMO.md              # 5-minute presentation script
└── out/                     # generated database and reports (gitignored)
```

---

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers timestamp edge cases (syslog year rollover, HTTP offsets), URL decoding, parser robustness, rule validation, window/cooldown/distinct semantics, end-to-end detection of all five demo incidents, SQLite round-trips, HTML escaping and CLI exit codes.

```text
Ran 35 tests in 0.16s
OK
```

---

## Design decisions

| Decision | Why |
|---|---|
| **Standard library only** | A university project should run on any machine with Python installed. No dependency drift, no virtualenv required. |
| **Batch, not streaming** | Log files can be sorted globally, which makes sliding windows deterministic and tests reproducible. A streaming version would need per-source watermarks. |
| **JSON rules, not code** | Detection logic stays declarative and reviewable by someone who does not write Python. |
| **SQLite** | A real database with indexes, transactions and SQL, in a single file with zero setup. |
| **Flat ECS-style fields** | Rules read like `source.ip`, not like object traversals. |
| **Explicit cooldowns** | Alert fatigue is a detection-engineering problem, not an afterthought. |
| **Escaped HTML output** | Log fields are attacker-controlled; the report must not render them as markup. |

---

## Limitations and responsible use

This is a learning tool, not a production security control:

* **Batch only.** It does not tail live logs, and it keeps correlation state in memory.
* **No authentication or authorization.** The database and report are plain files.
* **No threat intelligence, UEBA or anomaly detection.** Every alert comes from an explicit rule.
* **Single-node.** No distributed collection, no high availability, no retention policies.
* **Naive time handling for archived logs.** Syslog lines have no year; the parser infers it (current year, or the previous one near New Year).
* **Privacy.** Authentication logs contain personal data. Use synthetic or anonymized data in coursework, restrict access to `out/`, and follow your institution's rules and applicable law (e.g. LGPD in Brazil, GDPR in the EU). The demo only uses RFC 5737 documentation addresses.
* **Ethics.** Only analyze logs from systems you own or are explicitly authorized to test.

---

## Documentation

* [Architecture and design](docs/ARCHITECTURE.md)
* [Detection rule reference](docs/RULES.md)
* [Academic report](docs/REPORT.md)
* [Demo / presentation script](docs/DEMO.md)

## References

* Kent, K. & Souppaya, M. **NIST SP 800-92: Guide to Computer Security Log Management.** NIST, 2006.
* MITRE. **ATT&CK Enterprise Matrix.** <https://attack.mitre.org/>
* Elastic. **Elastic Common Schema (ECS).** <https://www.elastic.co/guide/en/ecs/current/index.html>
* OWASP. **OWASP Top 10 — A09:2021 Security Logging and Monitoring Failures.**
* ISO/IEC. **ISO/IEC 27035-1: Information technology — Security incident management.** 2023.

## License

MIT — see [LICENSE](LICENSE).
