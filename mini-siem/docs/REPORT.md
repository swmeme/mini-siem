# Mini-SIEM: Design and Evaluation of a Lightweight SIEM Pipeline in Pure Python

**Student:** _[Your name]_
**Course:** _[Course name]_
**Institution:** _[University / department]_
**Professor:** _[Professor name]_
**Date:** November 2026

---

## Abstract

Security Information and Event Management (SIEM) systems are central to modern security operations, but their cost and operational complexity make them difficult to study in a laboratory setting. This work presents **Mini-SIEM**, a lightweight SIEM pipeline implemented in pure Python with no third-party dependencies. The system collects Linux authentication logs, web server access logs and JSON application logs; normalizes them into a common, ECS-inspired field model; correlates them using declarative detection rules with sliding windows, grouping, distinct-value counting and alert cooldowns; persists events and alerts in SQLite; and produces a self-contained HTML incident report. A synthetic scenario containing five incidents — SSH brute force, SSH password spraying, web directory scanning, SQL injection and an application error burst — is detected by six rules mapped to MITRE ATT&CK, with a 100% parse rate on well-formed lines and a runtime of approximately 10 ms for 78 events. The project is validated by 35 automated tests covering parsing, correlation semantics, storage, report escaping and CLI behavior. The main contribution is pedagogical: a complete, auditable implementation of the SIEM data path that exposes the design decisions — especially normalization, correlation windows and alert suppression — that production platforms usually hide.

**Keywords:** SIEM; log management; detection engineering; correlation; MITRE ATT&CK; Python.

---

## 1. Introduction

### 1.1 Context

Every server, application and network device produces logs. Individually, a log line is a fact of limited value; collectively, logs are the primary evidence of what happened in an environment. The problem is volume and heterogeneity: an SSH daemon writes free-text syslog, a web server writes a different text format, and an application writes JSON with its own vocabulary. Correlating these sources manually is infeasible, and correlating them automatically is precisely the function of a SIEM.

Commercial SIEM platforms such as Splunk, Microsoft Sentinel, IBM QRadar and Elastic Security implement this function at scale, but they are expensive, closed in their internals, or require substantial infrastructure. For students and small organizations, this creates a gap: the concepts are taught, but the pipeline is rarely built end to end. As a result, detection engineering is often learned as rule syntax for a specific vendor rather than as a data problem.

### 1.2 Problem

The problem addressed here is **how to implement the essential SIEM data path in a way that is small enough to understand, complete enough to be useful, and rigorous enough to be evaluated**. "Essential" means collection, parsing, normalization, correlation, alerting, storage and reporting. "Small" means a single process, a single configuration file and no external services.

### 1.3 Objectives

**General objective:** design, implement and evaluate a mini-SIEM in Python that detects multi-source security incidents from log files.

**Specific objectives:**

1. Parse three representative log formats and normalize them into a common schema.
2. Implement a stateful correlation engine with sliding windows, grouping and cooldowns.
3. Express detections declaratively, including threshold rules and distinct-value counting.
4. Persist events and alerts for later investigation.
5. Produce an analyst-readable incident report.
6. Provide a reproducible incident scenario for demonstration and testing.
7. Validate behavior with automated tests.

### 1.4 Justification

Building the pipeline exposes decisions that using a SIEM hides: which fields to normalize, how long a window should be, when an alert should repeat, and how to avoid turning a report into an injection vector. These are the questions a detection engineer answers daily. A small implementation also makes the security properties of the tool itself auditable, which matters because a SIEM concentrates sensitive evidence.

### 1.5 Scope and delimitations

The system is a **batch** analyzer of log files. It does not tail live logs, distribute collection, enrich with threat intelligence, apply machine learning, or provide authentication and access control. It is not proposed as a production security control. The evaluation is a functional case study on a synthetic scenario, not a measurement of detection accuracy on real network traffic.

---

## 2. Theoretical background

### 2.1 Log management and SIEM

NIST SP 800-92 defines log management as the process of generating, transmitting, storing, analyzing and disposing of log data, and recommends centralized analysis because correlating events across systems is essential to detecting incidents [1]. A SIEM combines **Security Information Management** (collection, storage, analysis and reporting of log data) with **Security Event Management** (real-time monitoring, correlation and alerting) [2]. In practice, a SIEM is the operational layer that converts heterogeneous telemetry into prioritized alerts and retained evidence.

### 2.2 The pipeline model

The architecture used in this work follows the canonical pipeline:

1. **Collection** — acquire logs from sources.
2. **Parsing** — extract fields from each format.
3. **Normalization** — map fields to shared names and semantics.
4. **Correlation** — combine events across time and entities.
5. **Alerting** — assign severity and notify.
6. **Retention and reporting** — preserve evidence and communicate results.

Normalization is the stage that makes the rest possible. Without it, every rule is source-specific; with it, a rule about failed authentication can apply to sshd, a VPN or a web login endpoint. The Elastic Common Schema (ECS) is a widely used open specification for such field names [3]; Mini-SIEM adopts an ECS-inspired subset (`source.ip`, `user.name`, `event.action`, `event.outcome`, `url.path`, `http.response.status_code`).

### 2.3 Detection approaches

Four families are common:

| Approach | Description | Strength | Weakness |
|---|---|---|---|
| Signature | Match known indicators or patterns | Precise, explainable | Misses variants |
| Threshold | Count events per entity in a window | Simple, effective for brute force and floods | Requires tuning |
| Correlation | Relate different events or sources | Detects multi-stage behavior | More state and complexity |
| Anomaly / ML | Learn a baseline and flag deviations | Can find unknown behavior | Explainability and false positives |

Mini-SIEM implements signature and threshold rules, plus the correlation primitive of grouping events by entity over time. This covers the incidents in scope while keeping every alert explainable by a rule file.

### 2.4 MITRE ATT&CK

MITRE ATT&CK is a knowledge base of adversary tactics and techniques observed in real intrusions [4]. Mapping detections to technique IDs gives analysts a shared vocabulary and reveals coverage gaps. The rules in this project map to credential access (T1110.001, T1110.003), reconnaissance (T1595.002), initial access (T1190) and privilege escalation (T1548.003).

### 2.5 Related work

Wazuh is an open-source platform combining host intrusion detection, log analysis and compliance rules; it is powerful but requires agents and a manager. Elastic Security couples the Elastic Stack with detection rules and ECS-normalized data; Splunk is the commercial reference for search-based analysis. Academic surveys describe SIEM architectures, correlation techniques and open challenges such as alert fatigue and scalability [5].

Mini-SIEM differs from all of them in intent rather than capability: it implements a minimal version of the same stages, in one process, to make the mechanics inspectable and testable.

---

## 3. Methodology

### 3.1 Research approach

This is an **applied, exploratory study** with a **case-study evaluation**. The artifact is built according to explicit requirements, then exercised on a scenario with known ground truth. The evaluation asks three questions:

* **RQ1 — Functional coverage:** are all designed incidents detected, with the expected severity?
* **RQ2 — Robustness:** does malformed or irrelevant input degrade gracefully?
* **RQ3 — Reproducibility:** can the result be regenerated and verified automatically?

### 3.2 Requirements

| ID | Requirement | Verification |
|---|---|---|
| R1 | Ingest at least three log formats | Parser tests, demo |
| R2 | Normalize to a shared field model | Event inspection, rules |
| R3 | Support stateful threshold detection | Engine tests |
| R4 | Support distinct-entity correlation | Spray rule and test |
| R5 | Suppress duplicate alerts during an incident | Cooldown test |
| R6 | Persist events and alerts | Storage round-trip test |
| R7 | Generate an HTML report | Integration test |
| R8 | Run with a single command | CLI test |
| NF1 | No third-party runtime dependencies | `requirements.txt`, imports |
| NF2 | Deterministic results for fixed input | Demo seed and timestamps |
| NF3 | Graceful handling of malformed input | Parser and pipeline tests |
| NF4 | Safe rendering of untrusted log content | Escaping test |

### 3.3 Architecture

```text
┌─────────────┐   ┌──────────────┐   ┌───────────────────┐   ┌──────────────┐
│ Log sources │──►│   Parsers    │──►│ Normalized events │──►│ Correlation  │
│ auth/web/app│   │ auth/web/app │   │ ECS-style, UTC    │   │ (sliding     │
└─────────────┘   └──────────────┘   └───────────────────┘   │  windows)    │
                                                               └──────┬───────┘
                                                                      │ alerts
                                                      ┌───────────────┴───────────────┐
                                                      ▼                               ▼
                                               ┌─────────────┐                 ┌─────────────┐
                                               │   SQLite    │                 │ HTML report │
                                               └─────────────┘                 └─────────────┘
```

*Figure 1 — The Mini-SIEM pipeline. Log files are parsed into normalized events, sorted globally, correlated by the rule engine, then written to SQLite and an HTML report.*

The implementation is organized as a set of modules with acyclic dependencies: `models → parsers → rules → engine → pipeline → cli`, with `storage` and `report` as output leaves. A complete description is available in `docs/ARCHITECTURE.md`.

### 3.4 Detection engineering method

Each rule was derived from a hypothesis, not from an available log field:

1. **Hypothesis** — describe the adversary or failure behavior.
2. **Data** — identify which normalized fields observe it.
3. **Mechanism** — choose single-event, threshold or distinct counting.
4. **Baseline** — set count and window from the behavior's natural time scale.
5. **Test** — positive case (must fire) and negative case (must not fire).
6. **Tune** — record expected false positives and suppression strategy.
7. **Map** — assign severity, tags and ATT&CK technique.

### 3.5 Evaluation procedure

The demo generator creates one scenario containing five incidents and a background of legitimate activity. The scan is run, and the resulting alert set is compared with the ground truth. Parse rates, runtime and test results are recorded. Unit and integration tests are executed with `python -m unittest`.

---

## 4. Implementation

### 4.1 Technology stack

| Component | Choice | Rationale |
|---|---|---|
| Language | Python 3.12 (3.10+) | Readability, standard-library coverage |
| Parsing | `re`, `json` | No dependencies |
| Correlation | `collections.deque` | O(1) append and eviction at both ends |
| Storage | SQLite (`sqlite3`) | Transactions, indexes, single file |
| Reporting | String templates + CSS | Offline, self-contained, print-friendly |
| Testing | `unittest` | Standard library, no plugin |

The project deliberately avoids `pandas`, `pydantic`, `rich` and `pyyaml`. The cost is some manual validation code; the benefit is that the project runs on any machine with Python, which is a practical requirement for coursework and reproducibility.

### 4.2 Parsing and normalization

| Parser | Format | Extracted fields |
|---|---|---|
| `auth` | Linux syslog (sshd, sudo) | action, outcome, user, target user, source IP/port, host, command line |
| `web` | Apache/Nginx combined | method, path, query, status, bytes, referrer, user agent |
| `app` | JSON Lines | level, service, message, user, source IP, arbitrary `app.*` fields |

Three implementation details are worth highlighting:

* **Locale-independent timestamps.** Month abbreviations are mapped manually instead of using `strptime("%b")`, which depends on the process locale. A log generated on an English server must parse on a Portuguese workstation.
* **Year inference for syslog.** Syslog lines omit the year. The parser selects the current year unless that would place the event more than two days in the future, in which case it selects the previous year. This handles archived logs and the New Year boundary without configuration.
* **URL decoding before detection.** Paths are decoded with `unquote` and query strings with `unquote_plus`, so a rule sees `1' OR '1'='1` rather than `1%27+OR+%271%27%3D%271`. Detection on encoded payloads is a common source of false negatives.

Malformed or irrelevant lines return `None`. They are counted per source and reported as a parse rate; they never interrupt the scan.

### 4.3 Correlation engine

The engine receives events sorted by timestamp and keeps one bucket per `(rule, grouping key)`:

```text
for event in events:
    for rule in enabled_rules:
        if not rule.matches(event): continue
        if rule.is_single_event_ungrouped:
            emit(rule, [event]); continue

        key = rule.group_key(event)
        if key is None: continue

        bucket = buckets[(rule, key)]
        bucket.append(event)
        evict_events_older_than(rule.window)

        if bucket.meets_threshold() and bucket.cooldown_elapsed():
            emit(rule, bucket)
            bucket.last_alert = event.timestamp
```

Threshold evaluation has two modes: event count and distinct values of a field. The latter is required to separate brute force (one account, many attempts) from spraying (many accounts, few attempts each). Cooldowns prevent a sustained attack from generating one alert per event.

Complexity is `O(E × R + E)` time and `O(W)` memory for the events retained in active windows, where `E` is the number of events, `R` the number of rules and `W` the number of events inside windows. The global sort adds `O(E log E)`.

### 4.4 Rule model

Rules are JSON objects with an `id`, `title`, `severity`, optional `dataset`, a `match` map, an optional `group_by`, a `threshold` and an optional `cooldown_seconds`. Match values support exact strings, lists (OR), regular expressions and negation. Validation rejects empty matches, invalid regexes, thresholds without grouping or window, and duplicate IDs at load time.

```json
{
  "id": "SSH-PASSWORD-SPRAY-002",
  "title": "SSH password spraying across multiple accounts",
  "severity": "high",
  "dataset": "auth",
  "match": { "event.action": "login_failed" },
  "group_by": ["source.ip"],
  "threshold": { "count": 5, "window_seconds": 300, "distinct_by": "user.name" },
  "cooldown_seconds": 300,
  "mitre": ["T1110.003"]
}
```

### 4.5 Storage

The SQLite schema separates indexed columns (timestamp, dataset, source IP, user, severity, rule) from a JSON blob containing the complete normalized event and the original raw line. Alerts store severity score, entity label, event count, first/last seen, tags, MITRE IDs and up to 20 linked event IDs. This hybrid layout allows SQL filtering without a migration whenever a new field is introduced.

### 4.6 Reporting

The HTML report is generated from the same aggregates used by the console summary: event and alert totals, high/critical count, adaptive alert timeline, alert table sorted by severity, events per dataset, rules triggered, top source IPs among failed events and scan metadata. Every dynamic value is escaped with `html.escape`; a test verifies that a `<script>` string in a log field cannot become executable markup in the report.

### 4.7 Code quality

The code uses dataclasses for the data model, type hints on public interfaces, explicit exceptions (`ConfigError`, `RuleError`, `PipelineError`), and no global mutable state. The CLI maps failures to exit code 1, successful scans to 0, and `--fail-on <severity>` to 2, which allows the tool to be used as a CI gate.

---

## 5. Results

### 5.1 Scenario

The demo generates logs 20 minutes before the current time, using only RFC 5737 documentation addresses.

| Incident | Source | Behavior | Ground-truth rule |
|---|---|---|---|
| I1 | auth | 12 failed root logins from 203.0.113.66 in 84 s | SSH-BRUTEFORCE-001 |
| I2 | auth | 8 distinct users attempted from 198.51.100.23 in 126 s | SSH-PASSWORD-SPRAY-002 |
| I3 | web | 24 HTTP 404 responses from 192.0.2.99 in 46 s | WEB-DIRECTORY-SCAN-003 |
| I4 | web | 4 SQL injection payloads from 192.0.2.44 | WEB-SQL-INJECTION-004 |
| I5 | app | 12 ERROR records from `billing` in 33 s | APP-ERROR-BURST-006 |
| — | auth | Legitimate sudo to root by `alice` | PRIV-SUDO-ROOT-005 (context) |

The scenario also contains legitimate logins, normal storefront traffic, cron lines and one invalid JSON line.

### 5.2 Detection results

| Metric | Value |
|---|---|
| Events parsed | 78 |
| Parse rate — auth | 25/27 (92.6%) |
| Parse rate — web | 36/36 (100%) |
| Parse rate — app | 17/18 (94.4%) |
| Rules evaluated | 6 |
| Alerts raised | 6 |
| Incidents detected | 5/5 |
| Critical / high / medium / low | 1 / 2 / 2 / 1 |
| Runtime | ≈ 0.01 s |

The two auth lines not parsed are cron entries, which are irrelevant to the rules; the app line is deliberately invalid JSON. The skips demonstrate graceful degradation rather than failure.

Example console output:

```text
[critical     ] 2026-11-16T20:21:30Z  WEB-SQL-INJECTION-004        1 events  source.ip=192.0.2.44
[high         ] 2026-11-16T20:24:12Z  SSH-PASSWORD-SPRAY-002       5 events  source.ip=198.51.100.23
[high         ] 2026-11-16T20:19:28Z  SSH-BRUTEFORCE-001           5 events  source.ip=203.0.113.66, user.name=root
[medium       ] 2026-11-16T20:25:27Z  APP-ERROR-BURST-006         10 events  service.name=billing
[medium       ] 2026-11-16T20:18:28Z  WEB-DIRECTORY-SCAN-003      20 events  source.ip=192.0.2.99
[low          ] 2026-11-16T20:28:40Z  PRIV-SUDO-ROOT-005           1 events  user.name=alice
```

The brute-force alert reports five events, not twelve, because the cooldown prevents duplicates while the attack continues. This is intentional: the alert represents an incident, and the remaining events are still stored for investigation.

### 5.3 Test results

| Layer | Tests | Focus |
|---|---|---|
| Parsers | 14 | Field extraction, offsets, year rollover, URL decoding, malformed input |
| Rules and engine | 12 | Operators, validation, windows, grouping, distinct counting, cooldown |
| Pipeline, storage, report, CLI | 9 | End-to-end detections, ordering, SQLite, escaping, exit codes |
| **Total** | **35** | **All passing in ≈ 0.16 s** |

`python -m unittest discover -s tests -v` returns `OK`.

### 5.4 Reproducibility

`python -m minisiem demo` regenerates logs, database and report from scratch. The scenario is deterministic except for absolute timestamps. `python -m minisiem run --fail-on high` returns exit code 2 on the demo data, which was verified in the test suite.

---

## 6. Discussion

### 6.1 Objectives assessment

All specific objectives were met: three parsers (R1), a shared normalized schema (R2), stateful thresholds (R3), distinct counting (R4), cooldowns (R5), SQLite persistence (R6), an HTML report (R7) and a single-command workflow (R8). Non-functional requirements were also met: no runtime dependencies (NF1), deterministic demo (NF2), graceful malformed-input handling (NF3) and escaped reporting (NF4).

### 6.2 Design trade-offs

The most consequential decision was **batch processing with a global sort**. It makes correlation correct and tests deterministic, at the cost of holding all events in memory. A streaming design would need watermarks and handling of late events, which is a much larger engineering problem.

The second decision was **JSON instead of code or YAML** for rules. JSON is stricter than YAML (fewer silent type surprises) and safer than executable Python rules, but it is more verbose and cannot express joins between events. The `distinct_by` primitive covers the most important correlation case in the scenario; a production system would also need sequence rules ("success after N failures") and time-of-day conditions.

Using **SQLite** rather than a search engine keeps setup at zero and demonstrates SQL and indexing, but it cannot support full-text search over millions of events. The report is generated by scanning data, not by querying an analytics engine.

### 6.3 False positives and false negatives

The scenario includes normal traffic, and no rule fired on it, but this is weak evidence: the normal traffic was generated by the same author who wrote the rules. Real evaluation would require a baseline period and analyst feedback.

Known risks:

* **Shared egress addresses** can trigger spraying or scanning rules. Grouping by IP is a modeling assumption; NAT breaks it.
* **Authorized scanners** will trigger the scanning and SQL injection rules. An allowlist or a test-window tag would be needed in production.
* **Slow attacks** below the threshold are missed. This is the classic threshold trade-off: lower counts increase sensitivity and noise.
* **Legitimate sudo** is reported as low severity; the rule is an audit trail, not an accusation.
* **Application errors** are operational signals and may not indicate an adversary; the severity reflects availability impact.

These limitations are documented rather than hidden, which is itself part of detection engineering: a rule without a stated false-positive profile is incomplete.

### 6.4 Security and privacy

A SIEM centralizes sensitive data and is therefore a high-value target.

* **Log injection.** Report fields are escaped. Without this, a request path containing `<script>` would execute in the analyst's browser. This is tested.
* **Parser safety.** Unexpected parser exceptions are caught and counted, preventing a malformed line from stopping an investigation.
* **No network access.** The tool makes no outbound connections, reducing its attack surface.
* **Personal data.** Authentication logs contain usernames and IP addresses. In Brazil, processing must observe the LGPD; in the EU, the GDPR. Coursework should use synthetic or anonymized logs, and any real deployment needs a legal basis, retention limits and access control.
* **Ethics.** Log analysis must be restricted to systems the analyst owns or is authorized to monitor. The demo uses documentation address ranges precisely to avoid implying otherwise.

### 6.5 Threats to validity

* **Internal validity:** the demo and the rules share an author, so the scenario may be easier than reality. Mitigation: negative tests and normal background traffic.
* **External validity:** one synthetic dataset, three formats and six rules do not represent an enterprise environment.
* **Construct validity:** "detected" means "an alert with the expected rule ID was produced"; it does not measure investigation quality.

### 6.6 Lessons learned

1. **Normalization is the hard part.** Most implementation effort went into timestamps, URL decoding and field naming, not into detection logic.
2. **Suppression is part of detection.** A rule that fires on every event is not an alerting system; cooldowns and grouping are first-class features.
3. **Distinct counting is a small idea with large impact.** It is the difference between a noisy brute-force rule and a useful spraying detector.
4. **Tests force clarity.** Writing negative tests exposed ambiguity in window boundaries and cooldown semantics.
5. **Reports are attack surface.** Any tool that displays untrusted log data must treat output encoding as a security requirement.

---

## 7. Conclusion

Mini-SIEM demonstrates that the complete SIEM data path can be implemented in a small, readable and testable Python codebase. The system parses three log formats, normalizes them into an ECS-inspired schema, correlates events with sliding windows and distinct-value counting, suppresses duplicate alerts, stores evidence in SQLite and produces an analyst-readable HTML report. On a scenario with five incidents, six rules produced six alerts in the expected severity bands, with no false positives on the included background traffic, and 35 automated tests pass.

The project's value is primarily educational: it makes visible the decisions that commercial platforms abstract away. It is not a replacement for a production SIEM, and the report discusses the limitations of batch processing, IP-based grouping and threshold tuning.

### Future work

* Streaming ingestion with bounded lateness and per-source watermarks.
* Sequence rules (for example, successful login after repeated failures).
* Sigma rule import and export, to reuse community detections.
* Threat intelligence enrichment and allowlists.
* Additional parsers (Windows Event Log, cloud audit logs, VPN).
* Alert delivery (e-mail, Slack, webhooks) and a small web dashboard.
* Retention policies and database rotation.
* Evaluation against a public log dataset with labelled incidents.

---

## References

[1] K. Kent and M. Souppaya, *Guide to Computer Security Log Management*, NIST Special Publication 800-92, National Institute of Standards and Technology, Gaithersburg, MD, 2006.

[2] P. Bhatt, P. K. Manadhata, and L. Zomlot, "The Operational Role of Security Information and Event Management Systems," *IEEE Security & Privacy*, vol. 12, no. 5, pp. 35–41, 2014.

[3] Elastic, *Elastic Common Schema (ECS) Reference*. Available at: <https://www.elastic.co/guide/en/ecs/current/index.html>. Accessed: November 2026.

[4] MITRE, *ATT&CK Enterprise Matrix*. Available at: <https://attack.mitre.org/>. Accessed: November 2026.

[5] G. González-Granadillo, S. González-Zarzosa, and R. Diaz, "Security Information and Event Management (SIEM): Analysis, Trends, and Usage in Critical Infrastructures," *Sensors*, vol. 21, no. 14, art. 4759, 2021.

[6] P. Cichonski, T. Millar, T. Grance, and K. Scarfone, *Computer Security Incident Handling Guide*, NIST Special Publication 800-61 Rev. 2, National Institute of Standards and Technology, Gaithersburg, MD, 2012.

[7] OWASP Foundation, *OWASP Top 10:2021 — A09:2021 Security Logging and Monitoring Failures*. Available at: <https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/>. Accessed: November 2026.

[8] ISO/IEC, *ISO/IEC 27035-1:2023 — Information technology — Security incident management — Part 1: Principles and process*, 2023.

[9] Python Software Foundation, *Python 3 Documentation*. Available at: <https://docs.python.org/3/>. Accessed: November 2026.

[10] SQLite Consortium, *SQLite Documentation*. Available at: <https://www.sqlite.org/docs.html>. Accessed: November 2026.
