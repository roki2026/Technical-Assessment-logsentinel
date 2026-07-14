# LogSentinel

A command-line security log analyzer. Point it at your logs and it identifies
potential security incidents — brute force, injection, reconnaissance,
credential access, C2 beaconing, cloud and container attacks, and more — across
multiple file formats, with configurable rules and clear, actionable output.

Runs two ways: **batch** (analyze files and print a report) or **streaming**
(`--follow` a live log with bounded memory, emitting incidents as they happen).
Scales out across processes for high-volume hosts.

- **Zero dependencies** for core use (Python 3.8+ standard library). `PyYAML`
  only if you customize rules.
- **25 detection categories** spanning host, web, cloud, and container logs.
- **Configurable** — tune every threshold and add custom regex rules in YAML.
- **Production-ready** — streaming daemon, metrics/health endpoint, sharding,
  a supervisor, and a hardened systemd unit.

**What it is / isn't.** LogSentinel is a lightweight, self-contained detection
tool for individual hosts or small fleets — the kind of thing you can drop onto
a box and get useful alerts from in minutes. It is *not* a SIEM: no indexed
storage, no search UI, no distributed cluster. It complements those systems (or
stands in where running one would be overkill) rather than replacing them. See
[Limitations](#limitations) for the honest boundaries.

> Detection thresholds ship tuned for clean demonstration. **Calibrate them
> against your own baseline traffic before production** — see [Configuration](#configuration).

---

## Quickstart

```bash
# Analyze one or more log files (batch)
python3 logsentinel.py /var/log/auth.log /var/log/nginx/access.log

# With custom rules + machine-readable output
python3 logsentinel.py tests/fixtures/*.log tests/fixtures/*.jsonl \
        --rules rules.yaml --json report.json --csv report.csv

# Follow a live log continuously, emitting incidents as JSON-lines
python3 logsentinel.py /var/log/auth.log --follow --output incidents.jsonl
```

Exit codes: `0` clean · `1` non-critical findings · `2` at least one critical
(handy for cron/CI).

---

## What it detects

Host/auth, web, network, cloud, and container/IoT categories:

Brute force (SSH & web, including *failed-then-succeeded* compromises),
unauthorized access, password spraying, SSH username enumeration, SQL
injection, path traversal, webshells & malware indicators, reconnaissance
(scanner UAs, sensitive-file probing, 404 enumeration, vulnerability scans),
port scans, rate-limit abuse (volume-based and server-confirmed `429`), sudo
misuse & sensitive sudo commands, persistence, lateral movement, C2 beaconing,
credential attacks, data breaches / exfiltration, email/phishing, supply-chain,
cloud control-plane abuse (CloudTrail), container/Kubernetes escapes, IoT
default-credentials, policy violations, malformed lines, and **cross-file
correlation** (one actor stitched across multiple logs into a single
multi-stage incident).

Every finding includes severity, the entities involved (IPs/users/hosts), a
MITRE ATT&CK ID, a time window, and `file:line` evidence.

---

## Supported log formats

Auto-detected per line — mix them freely in one run:

| Format | Examples |
|---|---|
| Syslog | `auth.log`, `secure`, kernel/firewall, sudo, postfix |
| Apache/Nginx | Combined Log Format access logs |
| JSON lines | AWS CloudTrail, Kubernetes audit, generic app JSON |
| (unrecognized) | flagged as `malformed` — counted and reported |

---

## Usage

### Batch mode

```
python3 logsentinel.py FILE [FILE ...] [options]

--rules PATH          YAML rules/config (extends built-in defaults)
--json PATH           write full JSON report
--csv PATH            write CSV summary
--min-severity LEVEL  console filter: critical|high|medium|low|info
--year YEAR           year for syslog timestamps (they omit it)
--no-color            plain output for piping/CI
```

### Streaming mode (`--follow`)

Processes events one at a time and discards them, so memory stays flat
regardless of volume (measured: **~24 MB for 1M lines**, constant). Follows
files across rotation/truncation and checkpoints its position so restarts
neither lose lines nor re-alert.

```
--follow              enable streaming
--output PATH         append JSONL incidents to a file (else stdout)
--quiet               with --output, don't also echo to stdout
--checkpoint PATH     position checkpoint (default .logsentinel.ckpt; "" disables)
--cooldown SEC        suppress duplicate alerts per detector+entity (default 300)
--poll-interval SEC   idle poll delay (default 1.0)
--once                process available data then exit (cron/testing)
--metrics-port PORT   serve /health and /metrics over HTTP (0 = off)
--shard-index N       this shard's index (0-based)
--shard-total N       total shards (events assigned by source IP)
```

A sustained attack produces a handful of alerts carrying an
`occurrences_since_last_alert` count, not one per malicious line.

---

## Configuration

All configuration is optional and merges over built-in defaults — the tool
works with no config file. Tune thresholds, toggle detectors, and add custom
rules in `rules.yaml`:

```yaml
thresholds:
  brute_force: {count: 5, window_sec: 300}
  web_login_success_min_fails: 3      # fails-then-success compromise trigger
  rate_limit: {requests: 60, window_sec: 60}
  beacon_max_jitter: 0.15

internal_networks: ["10.", "192.168.", "172.16."]

detectors:                            # turn any detector on/off
  c2: true
  insider: false

pattern_rules:                        # custom regex rules EXTEND the built-ins
  - id: CUSTOM-001
    category: Policy Violations
    severity: low
    field: path                       # message | path | user_agent | process
    regex: "(?i)/internal-tools/"
    mitre: "-"
    description: "External access to internal-tools endpoint"
# replace_rules: true                 # discard built-ins entirely
```

**Calibration matters at scale.** The default `rate_limit` (60 req/60s) will
false-positive on busy sites; raise it to your real per-IP peak first.

---

## Running at scale

A single process handles ~10–15k lines/sec. For higher volume, run **shards**
over the same files (each processes only the events it owns, assigned by a
stable hash of source IP so all of one attacker's state stays in one process),
and merge their outputs with the **aggregator**. The **supervisor** launches and
monitors the whole fleet.

```bash
# Managed fleet: 4 shards + aggregator, health-monitored, auto-restart
python3 logsentinel_supervisor.py /var/log/nginx/access.log \
        --shards 4 --base-metrics-port 9200 \
        --dedup-window 60 --merged-output merged.jsonl
```

- `logsentinel_aggregator.py` — merges per-shard JSONL into one ordered stream,
  optional cross-shard dedup, own `/metrics`.
- `logsentinel_supervisor.py` — launches shards + aggregator, restarts failures
  with backoff, clean shutdown.

### Metrics & health

Add `--metrics-port 9200` to any streaming process:

- `GET /health` → `{"status":"ok"}` for liveness probes
- `GET /metrics` → JSON (lines processed, rate, incidents by severity/category, lag)
- `GET /metrics/prometheus` → Prometheus text format

### systemd

A hardened unit is in [`deploy/logsentinel.service`](deploy/logsentinel.service)
(runs the supervisor, read-only filesystem except its state dir, restart on
failure, bounded memory). Install:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin logsentinel
sudo mkdir -p /opt/logsentinel /var/lib/logsentinel
sudo cp logsentinel*.py rules.yaml README.md /opt/logsentinel/
sudo chown -R logsentinel:logsentinel /var/lib/logsentinel
sudo cp deploy/logsentinel.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now logsentinel
journalctl -u logsentinel -f
```

---

## Testing

```bash
# Verify all 25 detection categories still fire (regression gate; CI-friendly)
python3 tests/coverage_test.py

# Live-append load test (writer + follower + metrics polling)
python3 tests/live_load_test.py
```

`tests/fixtures/` holds multi-format sample logs, including a coordinated
multi-stage attack that spans files. `examples/` shows what a report looks like.

---

## Project layout

```
logsentinel.py               Core engine (parsers + 25 detectors, batch + streaming)
logsentinel_aggregator.py    Merge per-shard incident streams
logsentinel_supervisor.py    Launch & monitor a shard fleet
rules.yaml                   Default thresholds + custom rules
deploy/logsentinel.service   Hardened systemd unit
tests/                       coverage_test.py, live_load_test.py, fixtures/
examples/                    Sample report output
```

Production hosts need only `logsentinel.py`, the two scale-out scripts,
`rules.yaml`, and the service file. Tests and fixtures are for development/CI.

---

## Limitations

Worth knowing before you rely on it:

- **Detection finds indicators, not verdicts.** Evidence lines and MITRE IDs are
  there so a human can confirm quickly.
- **Thresholds need calibration** against your real traffic (see above).
- **Timestamps are treated as naive local time**; mixed-timezone log sets aren't
  reconciled.
- **Correlation and sharding key on source IP** — an attacker rotating IPs won't
  be linked, and cross-shard correlation isn't possible by design (each attacker
  lives in one shard). The aggregator can dedup identical alerts but not
  reconstruct correlation across shards.
- **Single-threaded ~10–15k lines/sec per process.** Fleet-scale volume needs
  sharding or a purpose-built pipeline downstream; LogSentinel is a lightweight,
  self-contained complement to those, not a replacement.

---

## Contributing

Issues and pull requests welcome. Before submitting a change to detection
logic, run the coverage gate and keep it green:

```bash
python3 tests/coverage_test.py     # must report 25/25
```

Design rationale, the detection model, and the reasoning behind the streaming
and sharding architecture are documented in [docs/DESIGN.md](docs/DESIGN.md).

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2025 roki.
