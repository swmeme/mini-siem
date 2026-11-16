# Architecture and Design

This document explains how the Mini-SIEM is built, why it is built that way, and where the boundaries are. It is meant to be read alongside the code; every section points at the module that implements the idea.

---

## 1. Goals and non-goals

### Goals

1. Demonstrate the complete SIEM data path: **collection → normalization → correlation → alerting → retention**.
2. Keep every stage small enough to be understood in one sitting.
3. Make detections declarative and reviewable (JSON rules).
4. Be reproducible: same inputs and configuration produce the same alerts.
5. Run anywhere with Python 3.10+ and zero third-party packages.
6. Be testable without fixtures that are hard to reason about.

### Non-goals

* Real-time streaming and tailing.
* Distributed collection, clustering, high availability.
* Machine learning, UEBA, threat intelligence feeds.
* Being a substitute for a production SIEM.
* Regulatory certification.

Those non-goals are deliberate. A project that claims to do everything usually demonstrates nothing well.

---

## 2. Component overview

```text
┌──────────────────────┐
│      config.json     │
│ sources / rules / db │
└──────────┬───────────┘
           │ Config.load()
           ▼
┌──────────────────────┐    one line     ┌──────────────────────┐
│  sources (files)     │ ──────────────► │  parsers.py          │
│  auth / web / app    │                 │  Auth / Web / App    │
└──────────────────────┘                 └──────────┬───────────┘
                                                    │ Event
                                                    ▼
                                         ┌──────────────────────┐
                                         │  normalize + sort    │
                                         │  pipeline.py         │
                                         └──────────┬───────────┘
                                                    │ list[Event]
                                                    ▼
                                         ┌──────────────────────┐
                                         │  engine.py            │
                                         │  sliding windows      │
                                         └──────────┬───────────┘
                                                    │ list[Alert]
                    ┌───────────────────────────────┼───────────────────────────────┐
                    ▼                               ▼                               ▼
         ┌──────────────────────┐       ┌──────────────────────┐       ┌──────────────────────┐
         │  console summary     │       │  storage.py (SQLite) │       │  report.py (HTML)    │
         │  report.py           │       │  events + alerts     │       │  self-contained      │
         └──────────────────────┘       └──────────────────────┘       └──────────────────────┘
```

### Module responsibilities

| Module | Responsibility | Depends on |
|---|---|---|
| `models.py` | `Event`, `Alert`, severity scale, ID/ISO helpers | — |
| `parsers.py` | Raw line → `Event` or `None`; timestamp parsing | `models` |
| `rules.py` | Rule schema, validation, matching, alert construction | `models` |
| `engine.py` | Stateful correlation over ordered events | `models`, `rules` |
| `config.py` | Load and validate `config.json`; resolve paths | `models`, `parsers` |
| `pipeline.py` | Orchestrate collection, parsing, sorting, detection | all of the above |
| `storage.py` | Persist/load events and alerts in SQLite | `models` |
| `report.py` | Aggregates, console summary, HTML report | `models` |
| `simulate.py` | Synthetic incident logs | stdlib only |
| `cli.py` | Argument parsing, exit codes, wiring | everything |

The dependency graph is acyclic and points inward: `cli → pipeline → engine → rules → models`. Storage and reporting are leaves, which makes them easy to replace.

---

## 3. Data flow in detail

### 3.1 Collection

`Config.load()` validates the file and resolves every relative path against the configuration file's directory. This means a project checkout can be moved, renamed or zipped and still run.

Each source declares:

```json
{ "name": "web", "parser": "web", "path": "samples/access.log", "host": "web01" }
```

`host` is optional and only used when the log format does not identify the server (access logs, for example). It is applied with `setdefault`, so a host present in the line always wins.

### 3.2 Parsing

Every parser implements one method:

```python
def parse(self, line: str) -> Event | None
```

* `None` means "not relevant / not recognized"; the pipeline increments a per-source skip counter.
* A malformed line must not raise. The pipeline additionally catches unexpected exceptions and counts them as skipped, so one exotic line cannot abort a scan of a million.

Timestamps are parsed manually rather than with `strptime`:

* `%b` (month abbreviation) is **locale-dependent**. On a Portuguese Windows install, `Dec` might not match `dez`, so a log shipped from a Linux server would silently fail. A fixed English month table removes that class of bug.
* Syslog timestamps have no year. The parser picks the current year unless that would place the event more than two days in the future, in which case it uses the previous year. This handles the New Year boundary without configuration.

URLs are decoded before matching. Paths use `unquote`; query strings use `unquote_plus` so that both `%20` and `+` become spaces. Detection rules therefore match what the application saw, not its percent-encoded form.

### 3.3 Normalization

The normalized schema is a flat dictionary of dotted fields. The core fields are:

| Field | Meaning | Example |
|---|---|---|
| `event.dataset` | Source family | `auth`, `web`, `app` |
| `event.action` | What happened | `login_failed`, `http_request`, `sudo_command` |
| `event.category` | Coarse class | `authentication`, `web`, `process`, `application` |
| `event.outcome` | Success/failure | `success`, `failure` |
| `user.name` | Actor | `alice` |
| `user.target.name` | Target of sudo | `root` |
| `source.ip` / `source.port` | Origin | `203.0.113.66` |
| `host.name` | Affected host | `web01` |
| `url.path` / `url.query` | HTTP request target | `/search`, `q=1 OR 1=1` |
| `http.response.status_code` | HTTP status | `404` |
| `log.level` | Application level | `ERROR` |
| `service.name` | Application service | `billing` |
| `message` | Human-readable summary | `Failed password for root ...` |

All values are stored as strings. This is a deliberate simplification: comparison is always well-defined, JSON serialization is trivial, and no rule needs to care about integer/string coercion. Numeric operators are not supported, and the documentation says so instead of pretending otherwise.

### 3.4 Ordering

After parsing, `pipeline.py` sorts all events by `(timestamp, dataset, id)`. Global ordering is what makes sliding windows correct when auth, web and application logs are read one file at a time. It is also the main memory cost of the design (see §7).

### 3.5 Correlation

`DetectionEngine.process(events)` iterates once over the ordered events and once over the (usually small) rule set:

```text
for each event:
    for each enabled rule:
        if rule does not match event: continue
        if rule is single-event and ungrouped: emit alert; continue

        key = values of rule.group_by from event
        if any value missing: continue

        bucket = buckets[(rule, key)]
        bucket.append(event)
        evict events older than rule.window

        if threshold reached and cooldown elapsed:
            emit alert
            bucket.last_alert = event.timestamp
```

A bucket is just:

```python
@dataclass
class _Bucket:
    events: deque[Event]
    last_alert: datetime | None
```

Complexity is `O(E × R)` time, where `E` is the number of events and `R` the number of rules, plus the cost of eviction (each event enters and leaves a bucket at most once). Memory is proportional to the number of events retained inside active windows, not to the total input size.

**Why one pass?** The input is already sorted, so the oldest event in a bucket is always at the left of the deque. Eviction is `popleft()` until the window is satisfied. No re-sorting, no indexing, no database round-trips.

### 3.6 Alerting and retention

An `Alert` contains:

* rule identity and title, severity and score;
* entity label (`source.ip=..., user.name=...`);
* event count, first/last seen, up to 20 event IDs;
* description, tags and MITRE technique IDs.

The SQLite schema stores indexed columns for the fields an analyst filters on (`timestamp`, `dataset`, `source_ip`, `user_name`, `severity`, `rule_id`) and a JSON blob with the complete normalized event. This is a small version of the "indexed core + document" pattern used by real log platforms.

---

## 4. Detection model

### 4.1 Two families

| Family | State | Use case |
|---|---|---|
| Single event | None (or cooldown per entity) | SQL injection payload, sudo to root |
| Threshold | Sliding window | Brute force, scanning, error bursts |

A threshold rule with `count = 1` and a `group_by` behaves like a grouped single-event rule with a cooldown; this lets an analyst suppress duplicate alerts for the same entity without writing extra code.

### 4.2 Distinct counting

`distinct_by` changes the threshold from "number of events" to "number of different values of a field inside the window". Password spraying is the canonical example:

* brute force: same `(source.ip, user.name)`, many failures → threshold on events;
* spraying: same `source.ip`, many different `user.name` → threshold on distinct users.

Without this distinction, a spray would either be missed (if the rule groups by user) or generate a misleading brute-force alert (if it groups only by IP).

### 4.3 Cooldown

An attack that lasts ten minutes should not produce hundreds of identical alerts. After an alert, the bucket records `last_alert` and the rule will not fire again for that entity until `cooldown_seconds` (default: the window, or 60 s for windowless rules) has elapsed. The global `engine.cooldown_factor` scales all cooldowns for tuning without editing each rule.

### 4.4 Rule validation

`Rule.from_dict` is strict on purpose. It rejects:

* missing or malformed IDs and titles;
* unknown severity names;
* empty match conditions;
* invalid regular expressions (at load time, not at 3 a.m.);
* thresholds without a window or without a grouping key;
* `distinct_by` with a count of one;
* duplicate rule IDs across files.

A broken rule should stop the scan with a precise file name and message. Silent misconfiguration is worse than a failed start.

---

## 5. Storage design

```sql
events(id, timestamp, dataset, action, outcome, source_ip, user_name,
       host_name, message, fields JSON, raw)
alerts(id, timestamp, rule_id, title, severity, severity_score, entity,
       event_count, first_seen, last_seen, description, tags JSON,
       mitre JSON, event_ids JSON, dataset)
```

* `events.fields` preserves the complete normalized record; adding a field requires no migration.
* `events.raw` preserves the original line for evidence and re-parsing.
* `alerts.event_ids` links an alert to the events that caused it, capped at the 20 most recent to bound size.
* `PRAGMA journal_mode=WAL` improves concurrent read behavior (SQLite still allows only one writer).

The storage layer is intentionally thin. It offers `write`, `load_events`, `load_alerts` and `counts`; nothing else needs to know SQL.

---

## 6. Reporting

The HTML report is generated from in-memory data (during a scan) or from SQLite (`report` command). It has no JavaScript, no external CSS and no remote fonts, so it works offline and can be archived as evidence.

Rendering uses `html.escape` for every dynamic value. Log fields are attacker-controlled: a request path can contain `<script>`, and a report that renders it verbatim becomes a stored-XSS vector aimed at the analyst. This is tested explicitly.

Aggregates shown:

* total events, total alerts, high/critical count, failed events with a source IP;
* alert timeline (adaptive bin size, at most ~30 bars);
* per-severity and per-rule counts;
* top source IPs among failed events;
* events per dataset;
* scan metadata (configuration, sources, rules, duration, database).

---

## 7. Performance and limits

The design targets small environments: a laptop, a lab, a single host, a coursework dataset.

| Aspect | Behavior |
|---|---|
| Time | Linear in events × rules; 78-event demo runs in ~10 ms |
| Memory | All events are held in memory for sorting; buckets hold only active windows |
| Storage | SQLite file, no rotation or retention policy |
| Concurrency | Single process, single writer |
| Failure model | A missing log file aborts the scan with a clear error; malformed lines are skipped |

A streaming version would replace the global sort with per-source watermarks and bounded lateness, and would keep buckets in a database or cache. That is a natural extension, not a hidden requirement.

---

## 8. Security of the tool itself

A SIEM is a high-value target: it centralizes evidence and often contains personal data.

* **Input handling** — parsers are defensive; the pipeline catches parser exceptions.
* **Output encoding** — HTML is escaped; tests cover injection through log fields.
* **Path handling** — paths come from a trusted configuration file, not from log content.
* **No network access** — the tool makes no outbound connections, which also keeps the demo reproducible.
* **No credentials** — nothing authenticates, so the database and reports must be protected by file permissions and disk encryption.
* **Privacy** — logs contain usernames and IP addresses. Coursework should use synthetic data; production use would require retention limits, access control and a legal basis.

---

## 9. Extending the project

### Add a parser

1. Subclass `Parser` in `parsers.py` and implement `parse`.
2. Assign a unique `name`/`dataset`.
3. Register it in `PARSERS`.
4. Add tests with one valid and one malformed line.
5. Document the normalized fields it produces.

No other module changes.

### Add a rule

Create `rules/my_rule.json`, validate with `python -m minisiem rules`, and test against a real log sample. Tune `count`, `window_seconds` and `cooldown_seconds` using the false-positive notes in `docs/RULES.md`.

### Replace the output

`storage.py` and `report.py` are leaves. An integration with e-mail, Slack, a ticket system or Elasticsearch only needs to consume `list[Alert]`; the detection pipeline does not change.

---

## 10. Testing strategy

The suite is organized by layer:

* **Parsers** — field extraction, timestamp offsets, year rollover, URL decoding, malformed input.
* **Rules/engine** — condition operators, validation errors, duplicate IDs, window boundaries, grouping, distinct counting, cooldown scaling, disabled rules.
* **Pipeline/integration** — all five demo incidents detected, global ordering, host enrichment, SQLite round-trip, HTML escaping, CLI exit codes.

The demo generator doubles as a fixture: it produces known incidents with predictable volumes, so integration tests assert rule IDs rather than brittle timestamps.

```bash
python -m unittest discover -s tests -v
```

---

## 11. Design trade-offs (summary)

| Chosen | Alternative | Trade-off |
|---|---|---|
| Batch sort | Streaming with watermarks | Simpler and deterministic, uses more memory |
| JSON rules | Python/YAML rules | Safer and reviewable, no arbitrary code, less expressive |
| Flat fields | Nested ECS objects | Simple rules, risk of field-name sprawl |
| SQLite | Elasticsearch | Zero setup, no full-text search or scale |
| stdlib only | pandas/pydantic/rich | Portable, some manual validation code |
| Regex parsing | Grok/dissect | No dependency, less tolerance for format variants |
