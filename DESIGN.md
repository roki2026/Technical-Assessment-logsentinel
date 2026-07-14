# LogSentinel — Design Notes

This document explains how LogSentinel works internally and why it's built the
way it is. For usage, see the [README](../README.md).

## Goals

1. **Useful in minutes, no infrastructure.** A single Python file with no
   dependencies should give real detections on real logs. No database, no
   agent, no cluster.
2. **Honest signal.** Prefer detections a human can confirm from the evidence
   over black-box scoring. Every incident carries its raw evidence lines.
3. **Scale when needed, not before.** Batch for ad-hoc analysis; streaming for
   continuous monitoring; sharding for volume — each an opt-in step, not a
   rewrite.

## Pipeline

```
files ──▶ parse ──▶ normalize to Event ──▶ detectors ──▶ incidents ──▶ report/emit
```

**Parsing** auto-detects each line's format (syslog, Apache/Nginx combined,
JSON lines) and normalizes everything into one `Event` dataclass. A single
event model is the key simplification: every detector works against the same
fields regardless of source format, so adding a parser doesn't touch detectors
and vice versa. Unrecognized lines become `malformed` events (still counted —
they can indicate tampering or an unsupported format).

**Detection** has two engines:

- A **pattern-rule engine** driven entirely by config. Each rule is a regex
  over one field (`message`/`path`/`user_agent`/`process`) with its own
  category, severity, and MITRE ATT&CK ID. This covers everything expressible
  as "does this line match a signature" and is fully user-extensible without
  code.
- **Stateful detectors** for things a single line can't reveal: sliding
  time-window thresholds (brute force, rate abuse), per-entity aggregation
  (port scans, username enumeration), sequence logic (failures *then* a
  success), and interval analysis (C2 beaconing jitter).

**Cross-file correlation** runs last in batch mode: an actor appearing in
multiple detections across multiple files collapses into one "multi-stage
attack" incident, ordered along the kill chain. This turns a dozen scattered
alerts into one story.

## Detection philosophy

Two principles emerged from adversarial testing against realistic logs:

1. **Successful actions matter more than failed ones.** Most naive detectors
   watch for failures (failed logins, denied sudo). But *N failures followed by
   a success* is a compromise, and it often sits *below* the volume threshold a
   pure-count detector uses. LogSentinel treats failed-then-succeeded sequences
   as high-severity regardless of count. This single idea caught the most
   important incident in multiple test logs that a threshold-only approach
   missed entirely.

2. **Just-below-threshold is where attackers live.** Enumeration of a few
   usernames, a handful of sensitive-path probes, a short scan — each is under
   the "obvious attack" bar but meaningful in aggregate. Several detectors
   (username enumeration, vulnerability scan) exist specifically to catch
   low-volume activity that volume thresholds skip.

The tradeoff is false positives on busy legitimate traffic, which is why
thresholds are configurable and calibration is stressed everywhere.

## Streaming architecture

Batch mode holds all parsed events in memory (≈9–10× file size) because
correlation and beaconing analyze the whole dataset. That's fine for files,
fatal for continuous operation.

Streaming (`--follow`) inverts this: events are processed one at a time and
**discarded immediately**. State lives only in small, bounded per-entity
aggregates:

- Time-evicted: entries older than a TTL are dropped on a periodic sweep.
- Size-capped: each state table has a hard key ceiling; oldest entries evict.
- Result: **flat memory** (~24 MB measured for 1M lines) regardless of volume.

Detectors that need history (beaconing) keep a small bounded deque of recent
timestamps per key rather than all events. This is a deliberate accuracy
tradeoff — a beacon with an interval longer than the buffer window won't be
caught — in exchange for constant memory.

**Alert deduplication.** A per-`(detector, entity)` cooldown suppresses repeat
alerts within a window, attaching an `occurrences_since_last_alert` count
instead. Without this, a sustained brute force would emit one alert per line.

**Restart safety.** File positions are checkpointed (inode-aware, so rotation
and truncation are detected). On restart the tool resumes from the saved
offset: no lines lost, no re-alerting on already-seen lines.

## Sharding

A single Python process is CPU-bound around 10–15k lines/sec. To scale, run N
shards over the same files. Each shard reads every line (cheap) but only
*processes* events it owns.

Ownership is a **stable hash of source IP** (md5, not Python's per-process
randomized `hash()` — an early bug: randomized hashing sent the same IP to
different shards, breaking state locality and causing duplicate alerts). This
guarantees all of one attacker's activity lands in one process, so per-entity
state and single-actor correlation stay correct within a shard.

The **aggregator** merges per-shard JSONL outputs into one ordered stream, with
optional dedup for identical cross-shard alerts. The **supervisor** launches the
fleet plus aggregator and restarts failures.

**Known limit:** because ownership keys on IP, cross-shard *correlation* is
impossible by design — an attacker rotating IPs lands on different shards. The
aggregator can dedup identical alerts but cannot reconstruct correlation across
shards. Closing that gap would require shared state (e.g. Redis), which is
deliberately out of scope for a self-contained tool.

## Testing approach

`tests/coverage_test.py` feeds a minimal synthetic trigger for each of the 25
categories and asserts each fires — a fast regression gate, and a CI merge
check via its exit code. It proves each category *can* fire on a clean trigger;
it does **not** prove real-world completeness or absence of false positives.
That confidence comes from adversarial testing against realistic logs, which is
how most of the detection refinements above were found.

`tests/live_load_test.py` exercises the true streaming path: a writer appends
to a file at a target rate while the daemon follows it, and the harness polls
`/metrics` to confirm the daemon keeps up with a live-growing file.
