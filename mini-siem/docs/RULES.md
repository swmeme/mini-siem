# Detection Rule Reference

Rules live in `rules/` as one JSON object per file. They are loaded and validated at the start of every scan; an invalid rule stops the scan with the offending file name. This document defines the schema, the evaluation semantics and the tuning process.

---

## 1. Minimal rule

```json
{
  "id": "MY-RULE-001",
  "title": "Short human-readable name",
  "match": { "event.action": "login_failed" }
}
```

This fires **once per matching event**, because the default threshold is `count: 1` and there is no `group_by`.

## 2. Complete schema

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `id` | string | yes | — | Unique identifier; letters, digits, `_`, `.`, `-` |
| `title` | string | yes | — | Name shown in alerts and reports |
| `description` | string | no | `""` | Analyst-facing explanation |
| `severity` | string | no | `medium` | `informational`, `low`, `medium`, `high`, `critical` |
| `dataset` | string | no | any | Restrict to one source family (`auth`, `web`, `app`) |
| `match` | object | yes | — | Field conditions; **all** must match (logical AND) |
| `group_by` | string[] | no | `[]` | Correlation key; one bucket per distinct combination |
| `threshold.count` | integer | no | `1` | Events (or distinct values) required |
| `threshold.window_seconds` | integer | if count > 1 | `0` | Sliding window width |
| `threshold.distinct_by` | string | no | `null` | Count distinct values of this field instead of events |
| `cooldown_seconds` | integer | no | window or 60 | Minimum gap between alerts for one entity |
| `tags` | string[] | no | `[]` | Free-form labels for triage and reporting |
| `mitre` | string[] | no | `[]` | ATT&CK technique IDs |
| `enabled` | boolean | no | `true` | Set to `false` to keep a rule on disk but inactive |

Rules with `count > 1` **must** define `group_by` and `window_seconds`. A threshold without a grouping key is almost always a design mistake: it would count unrelated events across the whole environment as one incident.

---

## 3. Match conditions

A condition is a dotted field name mapped to one of:

| Form | Example | Semantics |
|---|---|---|
| Exact value | `"http.response.status_code": "404"` | String equality |
| List | `"http.response.status_code": ["403", "404"]` | OR over the list |
| Regular expression | `"url.query": { "regex": "union\\s+select" }` | Case-insensitive `re.search` |
| Negation | `"source.ip": { "not": "10.0.0.1" }` | Logical NOT |
| Dataset | `"dataset": "auth"` (top level) | Restricts the rule to one parser output |

All conditions in one `match` object must be true. There is no explicit OR between fields; use a list for OR on the *same* field, or write two rules.

Notes:

* Field names are case-sensitive; values are compared as strings.
* A missing field never matches, except under `not` (a missing field is "not equal", which is usually what a negation means).
* Regular expressions are compiled during validation, so a syntax error is reported before scanning.
* URL query strings are already URL-decoded, and query `+` becomes a space. Write rules against what the application received.
* There are no numeric operators, time-of-day conditions or joins between events. Those would require a richer rule language; the current scope is deliberately small.

### Useful field paths

| Path | Source | Example |
|---|---|---|
| `event.action` | all | `login_failed`, `http_request`, `sudo_command` |
| `event.outcome` | all | `success`, `failure` |
| `user.name` | auth, app | `alice` |
| `user.target.name` | auth (sudo) | `root` |
| `source.ip` | auth, web, app | `203.0.113.66` |
| `host.name` | auth, app, config | `web01` |
| `process.command_line` | auth (sudo) | `/usr/bin/apt-get update` |
| `url.path` | web | `/admin` |
| `url.query` | web | `q=1 OR 1=1` |
| `http.response.status_code` | web | `404` |
| `user_agent.original` | web | `sqlmap/1.7.2` |
| `log.level` | app | `ERROR` |
| `service.name` | app | `billing` |

---

## 4. Evaluation semantics

For each event, in chronological order:

1. **Dataset filter** — if the rule declares a dataset and the event belongs to another one, skip.
2. **Match** — evaluate every condition. No match, skip.
3. **Ungrouped single-event shortcut** — if `count == 1` and `group_by` is empty, emit an alert immediately. No state is kept.
4. **Grouping** — read every `group_by` field. If any is missing or empty, skip the event (a partial key would merge unrelated entities).
5. **Bucket** — append the event to the bucket for `(rule.id, key)`.
6. **Eviction** — remove events with `timestamp < now - window_seconds`.
7. **Threshold** — `len(bucket) >= count`, or `len(set(distinct values)) >= count`.
8. **Cooldown** — skip if the last alert for this bucket is newer than `cooldown_seconds × cooldown_factor`.
9. **Alert** — capture rule metadata, entity label, event count, first/last seen and up to 20 event IDs.

Because the pipeline sorts events globally before correlation, step 6 can stop at the first in-window event. The window is inclusive at both ends: an event exactly `window_seconds` old is still counted, and only strictly older events are evicted. This makes boundary behavior predictable and testable.

### Worked example

Rule: 5 failures, 120 s, grouped by `(source.ip, user.name)`, cooldown 120 s.

| Time | Event | Bucket size | Alert? |
|---|---|---|---|
| 10:00:00 | fail root from A | 1 | no |
| 10:00:30 | fail root from A | 2 | no |
| 10:01:00 | fail root from A | 3 | no |
| 10:01:30 | fail root from A | 4 | no |
| 10:02:00 | fail root from A | 5 | **yes** |
| 10:02:30 | fail root from A | 5 | no (cooldown) |
| 10:03:00 | fail root from A | 5 | no (cooldown) |
| 10:03:30 | fail root from A | 5 | no (cooldown) |
| 10:04:00 | fail root from A | 5 | **yes** (120 s elapsed, five events still in window) |

If the failures arrive every 40 s, the first event is evicted before the fifth arrives, the bucket never reaches five, and no alert is raised. This is the intended behavior: the events are too spread out to look like an attack. If the attack stops after the first alert, the bucket drains below the threshold and no repeat is emitted.

### Distinct counting

```json
"threshold": { "count": 5, "window_seconds": 300, "distinct_by": "user.name" }
```

The alert is raised when five **different** usernames fail from the same key. Repeating one username does not count toward the threshold. This is what distinguishes password spraying from brute force.

The alert's `event_count` is the number of events in the bucket, which may be larger than the distinct count. The report keeps both the evidence and the trigger clear.

---

## 5. Shipped rules

### SSH-BRUTEFORCE-001 — high

Five failed SSH passwords for the same `(source.ip, user.name)` inside 120 s.

* **Detects:** online guessing against a known account.
* **False positives:** automation with a stale credential, users who forget a newly rotated password.
* **Tuning:** raise `count` to 8–10 in environments with noisy deploy scripts; keep the window short (60–180 s) so slow guessing does not accumulate.

### SSH-PASSWORD-SPRAY-002 — high

Five distinct usernames failing from one `source.ip` inside 300 s.

* **Detects:** low-and-slow guessing across many accounts, designed to avoid per-account lockouts.
* **False positives:** NAT/proxy egress addresses shared by many users, vulnerability scanners with a wordlist.
* **Tuning:** a longer window (600 s) catches slower sprays; a higher count reduces noise from shared egress IPs.

### WEB-DIRECTORY-SCAN-003 — medium

Twenty HTTP 404 responses to one IP inside 60 s.

* **Detects:** content discovery (`ffuf`, `gobuster`, `dirb`, Nikto).
* **False positives:** broken links during a deploy, monitoring that probes removed endpoints, a single user with a stale bookmark set.
* **Tuning:** 20/60 s is aggressive on purpose for a small site. A large site with heavy crawler traffic may need 50–100 or `distinct_by: "url.path"` to count distinct missing paths instead of raw requests.

### WEB-SQL-INJECTION-004 — critical

The URL query matches SQL injection idioms: `UNION SELECT`, `' OR '1'='1`, `SLEEP(`, `INFORMATION_SCHEMA`, `WAITFOR DELAY`.

* **Detects:** automated and manual injection attempts that reach the application.
* **False positives:** security scanners during authorized tests, search terms that legitimately contain `union select`.
* **Tuning:** add patterns for your stack; keep the rule at critical only if the application is internet-facing and the query is actually passed to a database.

### PRIV-SUDO-ROOT-005 — low

A `sudo` command executed with target user `root`.

* **Detects:** privileged command execution for audit purposes.
* **False positives:** routine administration. This rule is low severity by design; in environments where root sudo is exceptional, raise it to medium or high.
* **Tuning:** add `process.command_line` regex conditions to focus on risky binaries (`/bin/sh`, `vim`, `find`, `nmap`), or exclude break-glass accounts.

### APP-ERROR-BURST-006 — medium

Ten ERROR records from one service inside 60 s.

* **Detects:** outages, failed deployments, dependency failures, and resource exhaustion.
* **False positives:** a single malformed request retried by a client, verbose logging during maintenance.
* **Tuning:** count 10/60 s suits a low-volume service. For a high-throughput API, use a rate relative to baseline or raise the count.
* **No ATT&CK mapping:** this is an operational availability signal, not every useful detection maps cleanly to an adversary technique. The empty `mitre` list is honest, not an omission.

---

## 6. Writing a new rule

### Step 1 — state the hypothesis

> "A client requesting many distinct sensitive paths in a short time is enumerating the application."

### Step 2 — identify the data

`url.path` exists in web events. Paths to count: `/admin`, `/.env`, `/backup.zip`, `/.git/config`.

### Step 3 — choose the mechanism

Distinct paths per IP inside two minutes, because a crawler may request the same page many times but a scanner tries many different paths.

### Step 4 — write it

```json
{
  "id": "WEB-SENSITIVE-PATHS-007",
  "title": "Requests to sensitive paths",
  "description": "One client requested five or more distinct sensitive paths within two minutes.",
  "severity": "medium",
  "dataset": "web",
  "match": {
    "url.path": { "regex": "^/(admin|\\.env|\\.git|backup|config|phpmyadmin)" }
  },
  "group_by": ["source.ip"],
  "threshold": { "count": 5, "window_seconds": 120, "distinct_by": "url.path" },
  "tags": ["web", "reconnaissance"],
  "mitre": ["T1595.002"]
}
```

### Step 5 — validate and test

```bash
python -m minisiem rules          # schema validation and listing
python -m minisiem run            # scan the sample logs
```

Add a test under `tests/` if the rule ships with the project. At minimum, verify that it fires on a synthetic sample and does **not** fire on normal traffic.

### Step 6 — tune

Run it against a representative period. For every alert ask:

* Was it a true positive? If yes, does the severity match the impact?
* If no, which condition was too broad: the match, the count, the window or the grouping?
* Would a cooldown reduce duplicates without hiding a new incident?

Record the decision in the rule's `description` so the next analyst understands the intent.

---

## 7. Severity scale

| Severity | Score | Meaning | Expected response |
|---|---|---|---|
| `informational` | 1 | Context, audit trail | No action |
| `low` | 2 | Worth recording, rarely actionable alone | Review periodically |
| `medium` | 3 | Suspicious or availability-impacting | Triage during the shift |
| `high` | 4 | Likely malicious or high impact | Investigate promptly |
| `critical` | 5 | Confirmed exploitation pattern or major outage | Immediate response |

The score drives console filtering (`alerts.min_severity`), the `--fail-on` exit code and the sort order in the report. Scores are intentionally coarse: five levels are enough for triage and easy to explain.

---

## 8. Rule author checklist

- [ ] Unique, descriptive ID with a numeric suffix.
- [ ] `title` says what was detected, not how.
- [ ] `description` explains the attacker behavior and intended response.
- [ ] `dataset` restricts the rule to the relevant source.
- [ ] `match` is as narrow as possible; no catch-all empty conditions.
- [ ] Grouping key identifies the entity an analyst would investigate.
- [ ] Threshold matches the behavior's natural time scale.
- [ ] Cooldown prevents duplicate alerts for a sustained incident.
- [ ] Severity reflects impact, not excitement.
- [ ] Tags and MITRE IDs are present when applicable.
- [ ] Positive **and** negative tests exist before shipping.
- [ ] The rule was run against real (or realistic) data and tuned.
