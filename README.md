# LogSentinel

A command-line security log analysis tool. It ingests one or more log files,
normalizes them into a common event model, applies configurable detection
rules, correlates activity **across files**, and reports potential security
incidents in console, JSON, or CSV form.

```bash
# Quick start
python3 logsentinel.py webserver.log auth.log

# Full run: custom rules, machine-readable outputs, syslog year override
python3 logsentinel.py logs/*.log cloudtrail.jsonl \
        --rules rules.yaml --year 2025 \
        --json report.json --csv report.csv
```

Requirements: Python 3.8+, no dependencies. `PyYAML` only if you use
`--rules` (`pip install pyyaml`).

---

## How it works

The pipeline has four stages:

**1. Input** — any number of files as positional arguments (shell globs work).
Missing files are skipped with a warning rather than aborting the run.

**2. Parsing** — each line is auto-detected and normalized into a single
`Event` model (timestamp, source IP, user, host, process, HTTP fields,
message, file, line number). One model means every detector works regardless
of source format. Supported formats:

| Format | Example source |
|---|---|
| Syslog | `auth.log`, `secure`, kernel/firewall, sudo, postfix |
| Apache/Nginx Combined Log | web access logs (user-agent optional) |
| JSON lines | AWS CloudTrail, Kubernetes audit, generic app logs |
| Anything else | flagged as a `malformed` event, counted and reported |

Request targets containing spaces (a common attack signal, e.g.
`?q=' UNION SELECT ...`) are preserved in full, not truncated at the first
space. Syslog lines omit the year; pass `--year` if the logs aren't from the
current year.

**3. Detection** — two complementary engines:

- **Pattern-rule engine** — fully config-driven. Each rule is a regex applied
  to one field (`message` / `path` / `user_agent` / `process`) with its own
  category, severity, and MITRE ATT&CK ID. Add, override, or disable rules in
  YAML without touching code.
- **Stateful detectors** — for behavior a single regex can't see: sliding
  time windows, per-IP aggregation, interval analysis, and sequence logic
  ("failures then a success").

**4. Output** — severity-sorted console report (colorized on TTYs) showing
category, entities (IPs / users / hosts), MITRE IDs, time window, and capped
raw-line evidence with `file:line` references. `--json` writes the complete
machine-readable report; `--csv` writes one incident per row for
spreadsheets or SIEM import.

---

## Detection coverage

**Sequence detectors** (the high-signal ones):
- **Brute force that SUCCEEDED** (SSH and web login): N failures followed by
  an accepted login from the same IP → critical, even *below* the raw volume
  threshold, because "failures then success" beats raw count.
- **Cross-file correlation**: one IP appearing in multiple detections across
  multiple files is merged into a single critical incident — either a
  **multi-stage attack** (different categories, ordered along the kill chain)
  or a **coordinated multi-service attack** (same category against several
  services, e.g. simultaneous SSH + web-login brute force).

**Threshold detectors**: SSH/web brute force, password spraying, SSH
username enumeration (`invalid user` probing below brute thresholds),
rate-limit abuse (volume-based **and** server-confirmed — any HTTP 429 is
trusted as the application's own judgment), 404 forced-browsing, vulnerability
scans (≥4 distinct admin/sensitive paths with 4xx, including 400s from attack
payloads), port scans (firewall `DPT=` logs), C2 beaconing (regular-interval
requests, jitter analysis), lateral movement (one account hopping internal
hosts), off-hours insider logins, and large-transfer exfiltration.

**Pattern rules**: SQL injection (incl. stacked queries / `DROP TABLE`), path
traversal, webshells and malware tooling, scanner user-agents, sensitive-file
probing (`.env`, `.git`, …), persistence (accounts/cron/services/SSH keys),
credential dumping, **sensitive sudo commands** (successful `sudo` touching
shadow/sudoers/SSH keys — benign admin commands like service restarts are
ignored), email/phishing, supply chain, cloud control-plane abuse
(CloudTrail: public buckets, `StopLogging`, key creation), container/K8s
escapes, IoT/default credentials, policy violations, and bulk data dumps.

Malformed/unparseable lines are always counted and reported (possible
tampering, corruption, or unsupported format).

---

## Configuration (`rules.yaml`)

Everything is optional and merges over built-in defaults — the tool works
with no config file at all. Three knobs:

```yaml
thresholds:                     # retune any detector
  brute_force: {count: 5, window_sec: 300}
  web_login_success_min_fails: 3   # fails-then-success compromise trigger
  invalid_user_enum: {count: 3}
  rate_limit: {requests: 60, window_sec: 60}
  beacon_min_requests: 6
  beacon_max_jitter: 0.15
  off_hours: {start: 0, end: 5}
  exfil_bytes: 50000000
  # ... see rules.yaml for the full list

internal_networks: ["10.", "192.168.", "172.16."]

detectors:                      # toggle any detector on/off
  c2: true
  insider: false

pattern_rules:                  # your rules EXTEND the built-ins
  - id: CUSTOM-001
    category: Policy Violations
    severity: low
    field: path                 # message | path | user_agent | process
    regex: "(?i)/internal-tools/"
    mitre: "-"
    description: "External access to internal-tools endpoint"
# replace_rules: true           # discard built-ins entirely
```

**Important**: the default thresholds are tuned for demonstrable precision on
small samples. Before production use, calibrate against your own baseline
traffic — a busy web server will need higher rate/404 thresholds.

---

## Continuous streaming mode (`--follow`)

For high-volume, always-on monitoring, run in streaming mode instead of batch:

```bash
# Follow files, emit incidents live as JSON-lines, survive restarts
python3 logsentinel.py /var/log/auth.log /var/log/nginx/access.log \
        --follow --output /var/log/logsentinel-incidents.jsonl \
        --checkpoint /var/lib/logsentinel/pos.ckpt
```

**Bounded memory.** Events are processed one at a time and discarded; only
small, time-evicted, size-capped per-entity aggregates are retained. Measured:
streaming 1,000,000 lines used **24 MB peak RSS** versus **896 MB** for the
same file in batch mode — and streaming memory is *constant*, so a billion
lines uses the same 24 MB. Throughput is ~13k lines/sec single-threaded.

**Rotation & restart safe.** File positions are checkpointed (inode-aware, so
log rotation and truncation are detected). On restart the tool resumes from
the saved offset: no lines lost, no duplicate alerts on already-seen lines.

**Alert deduplication.** A per-(detector, entity) cooldown (`--cooldown`,
default 300s) means a sustained attack produces a handful of alerts carrying an
`occurrences_since_last_alert` count, not one alert per malicious line.

**Same detection coverage** as batch — all 25 categories fire in streaming
mode, including live cross-source correlation.

Streaming flags:
```
--follow              enable streaming mode
--output PATH         append JSONL incidents to file (else stdout)
--quiet               with --output, don't also echo to stdout
--checkpoint PATH     position checkpoint (default .logsentinel.ckpt;
                      pass empty string to disable)
--cooldown SEC        duplicate-alert suppression window (default 300)
--poll-interval SEC   idle poll delay (default 1.0)
--once                process available data then exit (cron/testing)
```

### Metrics & health endpoint

Add `--metrics-port 9200` to expose an HTTP endpoint (daemon thread, no deps):

- `GET /health` -> `{"status":"ok"}` for liveness/readiness probes
- `GET /metrics` -> JSON: lines processed, parse rate, incidents by
  severity/category, `seconds_since_last_line` (lag), uptime, shard id
- `GET /metrics/prometheus` -> Prometheus text format for scraping

```bash
python3 logsentinel.py /var/log/auth.log --follow \
        --output inc.jsonl --metrics-port 9200
curl localhost:9200/metrics
```

### Sharding for horizontal scale

A single process handles ~10-15k lines/sec. To go beyond that, run N shards
over the same file(s); each processes only the events it owns, assigned by a
**stable** hash of source IP so all state for one attacker stays in one
process (no split-brain, no duplicate alerts):

```bash
# 3 shards, each with its own output, checkpoint, and metrics port
for i in 0 1 2; do
  python3 logsentinel.py /var/log/nginx/access.log --follow \
    --shard-index $i --shard-total 3 \
    --output inc-$i.jsonl --metrics-port $((9200+i)) &
done
```

Every shard reads every line (cheap) but only *processes* its slice (the
expensive part), so detection work scales roughly linearly with shard count.
Checkpoints are automatically suffixed per shard. Verified: the union of
sharded output equals single-process output, with no attacker appearing in
two shards.

> Note on tuning at scale: the load test surfaced that the default
> `rate_limit` threshold (60 req/60s) is too low for busy sites and will
> false-positive on heavy legitimate IPs. Raise it to match your real
> per-IP peak before production — this is the calibration step called out
> above, now with a concrete number attached.

---

## Scaling out: aggregator + supervisor

Two companion tools turn a shard fleet into an operable service.

### Aggregator (`logsentinel_aggregator.py`)

Merges the per-shard JSONL outputs into one ordered stream, optionally
collapsing duplicates, with its own combined `/metrics` endpoint:

```bash
python3 logsentinel_aggregator.py "shard-*.jsonl" \
        --output merged.jsonl --dedup-window 60 --metrics-port 9300
```

- Follows all shard files (rotation-safe, checkpointed) like the daemon.
- Emits each poll's batch in **event-time order**, tagging every record with
  its `_shard_source`.
- `--dedup-window N` collapses incidents with the same
  category+severity+entities seen within N seconds (useful if an attacker's
  activity ever spans shards, or for noisy repeats). `0` keeps everything.

### Supervisor (`logsentinel_supervisor.py`)

Launches the whole fleet — N shard daemons **plus** the aggregator — and keeps
them alive:

```bash
python3 logsentinel_supervisor.py /var/log/nginx/access.log \
        --shards 4 --base-metrics-port 9200 \
        --dedup-window 60 --merged-output /var/log/logsentinel-merged.jsonl
```

- Assigns ports automatically: shard *K* -> `base+K`, aggregator -> `base+shards`.
- Monitors each child by process liveness **and** its `/health` endpoint;
  restarts any that die, with exponential backoff for fast-crash loops and a
  `--max-restarts` giveup cap.
- Creates a work dir (`--work-dir`, default `./logsentinel-run`) holding 
  shard output, per-shard checkpoint, the merged output, and a combined
  `supervisor.log`.
- Clean shutdown on SIGINT/SIGTERM: signals all children, waits, force-kills
  stragglers, prints a restart summary.
- `--run-seconds N` runs for a bounded time (handy for testing/cron).

This is the recommended way to run LogSentinel at scale: one supervisor process
to start under systemd, everything else managed beneath it.

### Deploying as a service

A production-ready systemd unit ships as `logsentinel.service`. It runs the
**supervisor** (which manages the shard fleet + aggregator), restarts on
failure, shuts children down cleanly on stop, and is security-hardened
(read-only filesystem except the state dir, no new privileges, restricted
syscalls/namespaces, bounded memory). Install:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin logsentinel
sudo mkdir -p /opt/logsentinel /var/lib/logsentinel
sudo cp logsentinel*.py rules.yaml README.md /opt/logsentinel/
sudo chown -R logsentinel:logsentinel /var/lib/logsentinel
sudo cp logsentinel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now logsentinel

# operate
systemctl status logsentinel
journalctl -u logsentinel -f
curl localhost:9200/metrics    # shard 0  (shard K -> 9200+K)
curl localhost:9204/metrics    # aggregator (base + shard count)
```

Edit the log paths, `--shards`, ports, and `--dedup-window` in the unit's
`ExecStart` to match your host. For a single low-volume host you can instead
point `ExecStart` at `logsentinel.py --follow` directly (no fleet), but the
supervised layout is the recommended default.

### Scaling beyond one process

Single-threaded Python tops out around 10-15k lines/sec. For higher sustained
volume: shard by log source across multiple instances (each with its own
checkpoint), or place LogSentinel downstream of a log shipper. Genuinely
fleet-scale pipelines (hundreds of MB/min) belong on purpose-built streaming
infrastructure; LogSentinel is a lightweight, self-contained complement.

---

## Analyst observations (context, not alerts)

Beyond incidents, the report includes a separate **Analyst Observations**
section for speculative linkages and semantic anomalies that deserve a
human's eye but shouldn't page anyone. They are excluded from severity
totals and never affect the exit code. Two heuristics ship built-in:

- **Post-compromise proximity** — a credential/persistence/exfiltration
  action by a *different* identity within a window (default 300s,
  `observation_proximity_sec`) after a confirmed compromise. Matches the
  classic post-exploitation sequence, but the logs alone can't prove the
  identities are linked — so it's a note, not an alert.
- **Session inconsistency** — a `[preauth]` connection close on an IP:port
  pair that previously produced an *accepted* login. The line parses
  cleanly, so it isn't "malformed" — it's semantically contradictory:
  possible log artifact, ordering issue, or tampering.

Observations appear in the console section, under `analyst_observations`
in the JSON report, and as `note`-severity rows in the CSV. Disable with
`detectors: {observations: false}`.

---

## Options and exit codes

```
--rules PATH          YAML config (extends defaults)
--json PATH           full JSON report (all evidence)
--csv PATH            one-incident-per-row summary
--min-severity LEVEL  console filter: critical|high|medium|low|info
--year YEAR           year for syslog timestamps (they omit it)
--no-color            plain output for piping/CI
```

Exit codes for CI/cron alerting: `0` clean · `1` non-critical findings ·
`2` at least one critical finding.

---

## Try it

The `tests/fixtures/` directory contains multi-format logs that exercise the full
detector range, including coordinated multi-stage attacks spanning files:

```bash
python3 logsentinel.py tests/fixtures/*.log tests/fixtures/*.jsonl --rules rules.yaml
```

## Design notes & known limits

- Detection was iteratively hardened against adversarial test logs. The cases
  that drove the most fixes: attacks *just below* volume thresholds,
  *successful* actions (vs. the failed ones detectors usually watch), payloads
  with spaces in URLs, and single-actor activity split across services/files.
  The false-positive traps (e.g. `?q=O'Brien`, legitimate `sudo systemctl
  restart`) stay clean.
- Timestamps are treated as naive local time; mixed-timezone log sets aren't
  reconciled.
- Correlation keys on source IP; attackers rotating IPs won't be linked.
- The tool flags *indicators*, not verdicts — evidence lines and MITRE IDs
  are there so a human can confirm quickly. Semantic anomalies (e.g. a
  `[preauth]` close on a port that already authenticated) parse cleanly and
  need human review.
