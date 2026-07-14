#!/usr/bin/env python3
"""
logsentinel_supervisor.py — launch and monitor a LogSentinel shard fleet.

Starts N sharded streaming daemons over the same log file(s), plus one
aggregator that merges their outputs. Monitors each child via its /health
endpoint and process liveness; restarts any that die (with backoff). Handles
clean shutdown on SIGINT/SIGTERM.

    python3 logsentinel_supervisor.py /var/log/nginx/access.log \
        --shards 4 --base-metrics-port 9200 \
        --merged-output /var/log/logsentinel-merged.jsonl \
        --dedup-window 60

Layout it creates (in --work-dir, default ./logsentinel-run):
    shard-0.jsonl ... shard-N.jsonl     per-shard incidents
    shard-K.ckpt                        per-shard file positions
    merged.jsonl                        aggregator output (or --merged-output)
    supervisor.log                      child stdout/stderr
Ports:
    shard K        -> base_metrics_port + K
    aggregator     -> base_metrics_port + shards
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DAEMON = os.path.join(HERE, "logsentinel.py")
AGG = os.path.join(HERE, "logsentinel_aggregator.py")


class Child:
    def __init__(self, name, cmd, health_url, logfile):
        self.name = name
        self.cmd = cmd
        self.health_url = health_url
        self.logfile = logfile
        self.proc = None
        self.restarts = 0
        self.last_start = 0
        self.backoff = 1.0

    def start(self):
        self.last_start = time.time()
        lf = open(self.logfile, "a")
        lf.write(f"\n=== {self.name} start {datetime_now()} "
                 f"(restart #{self.restarts}) ===\n")
        lf.flush()
        self.proc = subprocess.Popen(self.cmd, stdout=lf, stderr=lf)
        print(f"[supervisor] started {self.name} pid={self.proc.pid} "
              f"(restart #{self.restarts})", file=sys.stderr)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def healthy(self):
        """True if process is up AND (no health url OR health check passes)."""
        if not self.alive():
            return False
        if not self.health_url:
            return True
        try:
            with urllib.request.urlopen(self.health_url, timeout=2) as r:
                return json.load(r).get("status") == "ok"
        except Exception:
            # Health endpoint may not be bound yet right after start
            return (time.time() - self.last_start) < 10

    def stop(self, sig=signal.SIGTERM):
        if self.alive():
            try:
                self.proc.send_signal(sig)
            except ProcessLookupError:
                pass


def datetime_now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def build_fleet(args):
    work = args.work_dir
    os.makedirs(work, exist_ok=True)
    logf = os.path.join(work, "supervisor.log")
    children = []

    shard_outputs = []
    for k in range(args.shards):
        out = os.path.join(work, f"shard-{k}.jsonl")
        shard_outputs.append(out)
        ckpt = os.path.join(work, f"shard-{k}.ckpt")
        port = args.base_metrics_port + k
        cmd = [sys.executable, DAEMON, *args.files,
               "--follow",
               "--shard-index", str(k), "--shard-total", str(args.shards),
               "--output", out, "--quiet",
               "--checkpoint", ckpt,
               "--cooldown", str(args.cooldown),
               "--metrics-port", str(port)]
        if args.rules:
            cmd += ["--rules", args.rules]
        if args.year:
            cmd += ["--year", str(args.year)]
        children.append(Child(f"shard-{k}", cmd,
                              f"http://127.0.0.1:{port}/health", logf))

    # Aggregator over all shard outputs
    merged = args.merged_output or os.path.join(work, "merged.jsonl")
    agg_port = args.base_metrics_port + args.shards
    agg_ckpt = os.path.join(work, "aggregator.ckpt")
    agg_cmd = [sys.executable, AGG, *shard_outputs,
               "--output", merged, "--quiet",
               "--checkpoint", agg_ckpt,
               "--metrics-port", str(agg_port)]
    if args.dedup_window:
        agg_cmd += ["--dedup-window", str(args.dedup_window)]
    children.append(Child("aggregator", agg_cmd,
                          f"http://127.0.0.1:{agg_port}/health", logf))

    return children, merged, agg_port


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="logsentinel_supervisor",
        description="Launch & monitor a sharded LogSentinel fleet + aggregator.")
    ap.add_argument("files", nargs="+", help="log file(s) all shards follow")
    ap.add_argument("--shards", type=int, default=2, help="number of shard daemons")
    ap.add_argument("--base-metrics-port", type=int, default=9200,
                    help="shard K uses port+K; aggregator uses port+shards")
    ap.add_argument("--work-dir", default="./logsentinel-run",
                    help="directory for outputs, checkpoints, logs")
    ap.add_argument("--merged-output", help="aggregator merged output path "
                    "(default WORKDIR/merged.jsonl)")
    ap.add_argument("--dedup-window", type=int, default=0,
                    help="aggregator cross-shard dedup window (seconds)")
    ap.add_argument("--cooldown", type=int, default=300,
                    help="per-shard duplicate-alert cooldown")
    ap.add_argument("--rules", help="YAML rules passed to every shard")
    ap.add_argument("--year", type=int, help="syslog year for every shard")
    ap.add_argument("--max-restarts", type=int, default=20,
                    help="give up on a child after this many restarts")
    ap.add_argument("--check-interval", type=float, default=3.0,
                    help="seconds between health checks")
    ap.add_argument("--run-seconds", type=float, default=0,
                    help="stop after N seconds (0 = run until signalled; "
                         "for testing)")
    args = ap.parse_args(argv)

    if args.shards < 1:
        sys.exit("--shards must be >= 1")

    children, merged, agg_port = build_fleet(args)
    stop = {"flag": False}

    def _sig(_s, _f):
        print("\n[supervisor] shutdown requested", file=sys.stderr)
        stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    print(f"[supervisor] launching {args.shards} shard(s) + aggregator; "
          f"merged -> {merged}; metrics ports "
          f"{args.base_metrics_port}..{agg_port}", file=sys.stderr)
    for c in children:
        c.start()
        time.sleep(0.3)  # stagger port binds

    started = time.time()
    try:
        while not stop["flag"]:
            time.sleep(args.check_interval)
            for c in children:
                if stop["flag"]:
                    break
                if not c.alive():
                    code = c.proc.returncode if c.proc else "?"
                    print(f"[supervisor] {c.name} exited (code {code})",
                          file=sys.stderr)
                    if c.restarts >= args.max_restarts:
                        print(f"[supervisor] {c.name} exceeded max restarts "
                              f"({args.max_restarts}); leaving down",
                              file=sys.stderr)
                        continue
                    # backoff: if it crashed fast, wait longer
                    if time.time() - c.last_start < 5:
                        c.backoff = min(c.backoff * 2, 30)
                    else:
                        c.backoff = 1.0
                    time.sleep(c.backoff)
                    c.restarts += 1
                    c.start()
                elif not c.healthy():
                    print(f"[supervisor] {c.name} pid={c.proc.pid} "
                          f"failing health check", file=sys.stderr)
            if args.run_seconds and time.time() - started >= args.run_seconds:
                print(f"[supervisor] run-seconds reached; stopping",
                      file=sys.stderr)
                break
    finally:
        print("[supervisor] stopping children...", file=sys.stderr)
        for c in children:
            c.stop()
        deadline = time.time() + 8
        for c in children:
            remaining = max(0, deadline - time.time())
            try:
                if c.proc:
                    c.proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                print(f"[supervisor] force-killing {c.name}", file=sys.stderr)
                c.proc.kill()
        summary = {c.name: {"restarts": c.restarts} for c in children}
        print(f"[supervisor] stopped. restart summary: "
              f"{json.dumps(summary)}", file=sys.stderr)
        print(f"[supervisor] merged incidents in: {merged}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
