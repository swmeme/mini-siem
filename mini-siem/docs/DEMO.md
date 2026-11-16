# Five-Minute Demo Script

A presentation plan for a university evaluation. It assumes the project is already installed (it only needs Python 3.10+).

## Before you start

```bash
cd mini-siem
python -m unittest discover -s tests -q     # confirm: 35 tests OK
python -m minisiem demo                      # pre-generate the artifacts
```

Open a terminal in the project root and keep `out/demo/report.html` ready in a browser tab. Remove `out/demo` before the live run if you want to show generation from scratch.

---

## 0:00–0:45 — Problem

> "Every server produces logs, but each format is different: syslog, access logs, JSON. A SIEM is the layer that collects, normalizes and correlates them. Commercial SIEMs are huge; I built the same pipeline in a small, readable Python project to show how it works."

Show the three sample formats side by side (`samples/auth.log`, `samples/access.log`, `samples/app.jsonl`). Point out that the same failed login looks completely different in each.

## 0:45–1:30 — Architecture

Draw or show the diagram from the README:

```text
files -> parsers -> normalized events -> correlation -> alerts -> SQLite + HTML
```

Key sentence: **"normalization is what lets one rule work across sources."**

Mention the design constraints: standard library only, batch processing, JSON rules.

## 1:30–2:30 — Live run

```bash
python -m minisiem demo
```

While it runs, explain that it is generating three log files containing five incidents plus normal traffic, then scanning them.

Point at the summary:

* 78 events parsed, 6 rules evaluated;
* 6 alerts, spanning critical, high, medium and low;
* runtime around 10 ms.

## 2:30–4:00 — Interpret the alerts

Use this table (also in `docs/REPORT.md`):

| Alert | What happened | Why the rule fired |
|---|---|---|
| `WEB-SQL-INJECTION-004` (critical) | 4 SQLi payloads from 192.0.2.44 | query string matched `UNION SELECT` / `OR '1'='1` |
| `SSH-PASSWORD-SPRAY-002` (high) | 8 accounts tried from 198.51.100.23 | 5 **distinct** users failed in 300 s |
| `SSH-BRUTEFORCE-001` (high) | root tried 12 times from 203.0.113.66 | 5 failures for the same account in 120 s |
| `APP-ERROR-BURST-006` (medium) | billing logged 12 database timeouts | 10 ERROR records in 60 s |
| `WEB-DIRECTORY-SCAN-003` (medium) | 24 missing paths from 192.0.2.99 | 20 HTTP 404 in 60 s |
| `PRIV-SUDO-ROOT-005` (low) | alice ran `sudo apt-get` | audit trail for root sudo |

Then make the key technical point:

> "Brute force and spraying produce the same kind of event. The difference is the correlation key: brute force groups by IP **and** user; spraying groups by IP and counts **distinct users**. That is why `distinct_by` exists."

Also point out the cooldown: the brute-force rule saw 12 failures but reported 5 events, because it emitted one alert per incident instead of one per event.

## 4:00–4:30 — Report and evidence

Open `out/demo/report.html`.

Show:

* KPI cards and the adaptive alert timeline;
* the alert table with entity, event count and ATT&CK IDs;
* top source IPs (the three attacker addresses stand out);
* scan metadata (sources, rules, duration).

Mention: **all log fields are HTML-escaped**, because a request path can contain `<script>` and the report must not execute it.

## 4:30–5:00 — Validation and limits

```bash
python -m unittest discover -s tests -q
```

> "35 tests: parsers, timestamp edge cases, window and cooldown semantics, distinct counting, SQLite round-trip, HTML escaping and CLI exit codes. The project is a batch analyzer, not a production SIEM: no streaming, no threat intelligence, no authentication. Those are documented as future work."

---

## Likely questions

**Why not just use Splunk/Elastic?**
They solve the problem at scale, but they hide the pipeline. This project implements the same stages in code that can be read and tested. It is a teaching artifact, not a competitor.

**How do you avoid false positives?**
Grouping, thresholds, cooldowns, severity levels and tuning notes per rule. The scenario includes normal traffic to check for noise. Real tuning requires a baseline and analyst feedback — stated in the limitations.

**What happens with a malformed line?**
The parser returns `None`; the pipeline counts it as skipped and continues. A test covers invalid JSON and malformed access-log lines.

**How would you scale it?**
Streaming ingestion with per-source watermarks, a real index (Elasticsearch/OpenSearch), distributed collection, retention policies. The engine's state would move to a shared store.

**Why SQLite?**
Zero setup, real SQL, transactions and indexes in one file. The trade-off is no full-text search and no horizontal scale.

**Why JSON rules instead of Python?**
Declarative, reviewable by non-programmers, no arbitrary code execution. The cost is less expressiveness: no joins or time-of-day conditions yet.

**What is the difference between brute force and spraying?**
Brute force: many passwords for one account. Spraying: a few passwords across many accounts. The event stream is similar; the correlation differs, which is why the rules use different grouping and `distinct_by`.

**What about LGPD/GDPR?**
Logs contain personal data. Use synthetic data for coursework, restrict access to `out/`, define retention and a legal basis for any real deployment. The demo only uses RFC 5737 documentation addresses.

**What would you do with more time?**
Sequence rules (success after failures), Sigma import, threat intelligence, additional parsers, alert delivery, and evaluation on a labelled public dataset.

---

## Contingency

If the live demo fails:

1. Run `python -m minisiem run` on the static `samples/` (no generation step).
2. Open the previously generated `out/demo/report.html`.
3. Show the test output and the code of `engine.py` — the correlation logic is under 100 lines.

The static samples trigger the same six rules, so the narrative does not change.
