#!/usr/bin/env python3
"""
logsentinel_aggregator.py — merge per-shard incident streams into one.

Shards each write their incidents to a JSONL file (--output). This tool
follows all of those files (rotation-safe, checkpointed), merges them into a
single ordered stream, optionally collapses duplicates within a window, and
re-emits to stdout / a file / an HTTP metrics endpoint.

    # follow live shard outputs, merged to a single file
    python3 logsentinel_aggregator.py inc-*.jsonl \
            --output merged.jsonl --metrics-port 9300

    # one-shot merge of existing files (e.g. for testing / batch)
    python3 logsentinel_aggregator.py inc-0.jsonl inc-1.jsonl --once
"""

import argparse
import glob
import io
import json
import os
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


# --------------------------------------------------------------------------
# Rotation-aware follower for JSONL incident files (mirrors the daemon's)
# --------------------------------------------------------------------------

class JsonlFollower:
    def __init__(self, paths, checkpoint, once=False):
        self.paths = paths
        self.ckpt = checkpoint
        self.once = once
        self.state = {}
        if checkpoint and os.path.exists(checkpoint):
            try:
                self.state = json.load(open(checkpoint))
            except (json.JSONDecodeError, OSError):
                pass

    def save(self):
        if not self.ckpt:
            return
        try:
            tmp = self.ckpt + ".tmp"
            json.dump(self.state, open(tmp, "w"))
            os.replace(tmp, self.ckpt)
        except OSError as e:
            print(f"[!] aggregator checkpoint save failed: {e}", file=sys.stderr)

    def poll(self):
        """Yield (source_path, dict) for each new incident line."""
        for path in self.paths:
            if not os.path.isfile(path):
                continue
            try:
                stt = os.stat(path)
            except OSError:
                continue
            s = self.state.get(path)
            if (s is None or s.get("inode") != stt.st_ino
                    or stt.st_size < s.get("offset", 0)):
                s = {"inode": stt.st_ino, "offset": 0}
                self.state[path] = s
            if stt.st_size == s["offset"]:
                continue
            try:
                with io.open(path, "r", errors="replace") as f:
                    f.seek(s["offset"])
                    while True:
                        pos = f.tell()
                        line = f.readline()
                        if not line:
                            break
                        if not line.endswith("\n") and not self.once:
                            f.seek(pos)
                            break
                        s["offset"] = f.tell()
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield path, json.loads(line)
                        except json.JSONDecodeError:
                            # partial/corrupt line — skip, count upstream
                            continue
            except OSError as e:
                print(f"[!] aggregator read error {path}: {e}", file=sys.stderr)


# --------------------------------------------------------------------------
# Aggregator metrics
# --------------------------------------------------------------------------

class AggMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.start = time.time()
        self.ingested = 0
        self.emitted = 0
        self.deduped = 0
        self.by_severity = defaultdict(int)
        self.by_category = defaultdict(int)
        self.by_source = defaultdict(int)   # per shard file
        self.last_emit = None

    def on_ingest(self, src):
        with self._lock:
            self.ingested += 1
            self.by_source[os.path.basename(src)] += 1

    def on_emit(self, rec):
        with self._lock:
            self.emitted += 1
            self.by_severity[rec.get("severity", "?")] += 1
            self.by_category[rec.get("category", "?")] += 1
            self.last_emit = time.time()

    def on_dedup(self):
        with self._lock:
            self.deduped += 1

    def snapshot(self):
        with self._lock:
            up = time.time() - self.start
            return {
                "status": "ok",
                "uptime_sec": round(up, 1),
                "incidents_ingested": self.ingested,
                "incidents_emitted": self.emitted,
                "incidents_deduped": self.deduped,
                "by_severity": dict(self.by_severity),
                "by_category": dict(self.by_category),
                "by_source": dict(self.by_source),
                "seconds_since_last_emit":
                    round(time.time() - self.last_emit, 1) if self.last_emit else None,
            }


def start_metrics_server(metrics, port):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path in ("/health", "/healthz", "/"):
                body, ct = b'{"status":"ok"}', "application/json"
            elif self.path == "/metrics":
                body = json.dumps(metrics.snapshot(), indent=2).encode()
                ct = "application/json"
            else:
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    try:
        srv = HTTPServer(("0.0.0.0", port), H)
    except OSError as e:
        print(f"[!] aggregator metrics bind :{port} failed: {e}", file=sys.stderr)
        return
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[*] Aggregator metrics: http://0.0.0.0:{port}/metrics", file=sys.stderr)


# --------------------------------------------------------------------------
# Dedup key: same incident from >1 shard, or repeated within a window
# --------------------------------------------------------------------------

def dedup_key(rec):
    ents = rec.get("entities", {})
    ips = ",".join(sorted(ents.get("ips", []) or []))
    users = ",".join(sorted(ents.get("users", []) or []))
    return (rec.get("category", ""), rec.get("severity", ""), ips, users)


def expand_globs(patterns):
    files = []
    for p in patterns:
        matched = glob.glob(p)
        files.extend(matched if matched else [p])
    # de-dupe while preserving order
    seen, out = set(), []
    for f in files:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


def run(args):
    files = expand_globs(args.files)
    follower = JsonlFollower(files, args.checkpoint, once=args.once)
    metrics = AggMetrics() if args.metrics_port else None
    if metrics:
        start_metrics_server(metrics, args.metrics_port)
    out = open(args.output, "a") if args.output else None
    recent = {}                          # dedup_key -> last wallclock emit
    dedup_window = args.dedup_window
    stop = {"flag": False}

    def _sig(_s, _f): stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    known = "\n".join(f"    - {f}" for f in files)
    print(f"[*] Aggregator following {len(files)} shard stream(s):\n{known}",
          file=sys.stderr)
    if dedup_window:
        print(f"[*] Cross-shard dedup window: {dedup_window}s", file=sys.stderr)

    last_ckpt = time.time()
    ingested = emitted = 0
    try:
        while not stop["flag"]:
            # Collect this poll's batch, then emit in event-time order so the
            # merged stream is coherent even though shards write independently.
            batch = []
            for src, rec in follower.poll():
                ingested += 1
                if metrics:
                    metrics.on_ingest(src)
                rec["_shard_source"] = os.path.basename(src)
                batch.append(rec)
                if stop["flag"]:
                    break
            batch.sort(key=lambda r: r.get("event_time") or r.get("emitted_at") or "")

            for rec in batch:
                if dedup_window:
                    k = dedup_key(rec)
                    now = time.time()
                    last = recent.get(k)
                    if last is not None and now - last < dedup_window:
                        if metrics:
                            metrics.on_dedup()
                        continue
                    recent[k] = now
                    # prune old dedup keys occasionally
                    if len(recent) > 20000:
                        cutoff = now - dedup_window
                        for kk in [kk for kk, t in recent.items() if t < cutoff]:
                            recent.pop(kk, None)
                line = json.dumps(rec)
                if out:
                    out.write(line + "\n"); out.flush()
                if not out or not args.quiet:
                    print(line, flush=True)
                emitted += 1
                if metrics:
                    metrics.on_emit(rec)

            if time.time() - last_ckpt > 15:
                follower.save(); last_ckpt = time.time()
            if not batch:
                if args.once:
                    break
                time.sleep(args.poll_interval)
    finally:
        follower.save()
        if out:
            out.close()
        print(f"[*] Aggregated {ingested} incidents -> {emitted} emitted "
              f"({ingested - emitted} deduped)", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="logsentinel_aggregator",
        description="Merge per-shard LogSentinel incident streams into one.")
    ap.add_argument("files", nargs="+",
                    help="shard JSONL output files (globs like inc-*.jsonl OK)")
    ap.add_argument("--output", metavar="PATH", help="merged JSONL output file")
    ap.add_argument("--quiet", action="store_true",
                    help="with --output, don't also echo to stdout")
    ap.add_argument("--checkpoint", default=".logsentinel_agg.ckpt",
                    help="position checkpoint (empty string disables)")
    ap.add_argument("--dedup-window", type=int, default=0,
                    help="collapse identical incidents (same category+severity+"
                         "entities) seen within N seconds across shards "
                         "(0 = no dedup, keep everything)")
    ap.add_argument("--metrics-port", type=int, default=0,
                    help="serve combined /health and /metrics on this port")
    ap.add_argument("--poll-interval", type=float, default=0.5,
                    help="seconds between polls when idle")
    ap.add_argument("--once", action="store_true",
                    help="merge available data then exit")
    args = ap.parse_args(argv)
    if not args.checkpoint:
        args.checkpoint = None
    return run(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
