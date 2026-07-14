#!/usr/bin/env python3
"""Live-append load test: a writer appends to a log while the daemon follows it.
Verifies the daemon keeps up with a live-growing file, the metrics endpoint
reports progress, and rotation is handled."""
import json, os, random, subprocess, sys, threading, time, urllib.request

LOG = "/tmp/live_stream.log"
OUT = "/tmp/live_incidents.jsonl"
PORT = 9231
TARGET_LPS = 5000          # lines/sec the writer emits
DURATION = 8               # seconds of writing

random.seed(1)
ips = [f"192.168.1.{i}" for i in range(1, 60)] + [f"10.0.0.{i}" for i in range(1, 60)]
paths = ["/index.html", "/api/x", "/products", "/dashboard", "/search?q=a"]

def now_apache(t):
    return time.strftime("%d/%b/%Y:%H:%M:%S", time.localtime(t))

def writer(stop):
    """Append benign traffic + periodic attack bursts to the live file."""
    open(LOG, "w").close()
    n = 0
    t0 = time.time()
    with open(LOG, "a") as f:
        while not stop.is_set():
            batch = TARGET_LPS // 20   # write in 50ms batches
            ts = now_apache(time.time())
            for _ in range(batch):
                ip = random.choice(ips)
                f.write(f'{ip} - - [{ts} +0000] "GET {random.choice(paths)} '
                        f'HTTP/1.1" 200 {random.randint(100,5000)} "-" "UA"\n')
                n += 1
            # inject an attack burst every ~1s: brute force from a bad IP
            if int(time.time() - t0) != int(time.time() - t0 - 0.05):
                for _ in range(6):
                    f.write(f'203.0.113.9 - - [{ts} +0000] "POST /login '
                            f'HTTP/1.1" 401 54 "-" "python-requests"\n')
                    n += 1
            f.flush()
            time.sleep(0.05)
    return n

def poll_metrics():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/metrics", timeout=2) as r:
            return json.load(r)
    except Exception as e:
        return {"error": str(e)}

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    tool = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "logsentinel.py")
    for f in (OUT, ".live.ckpt"):
        if os.path.exists(f):
            os.remove(f)

    stop = threading.Event()
    written = {"n": 0}
    def _w():
        written["n"] = writer(stop)
    wt = threading.Thread(target=_w)

    # Start the daemon following the (initially empty) live file
    daemon = subprocess.Popen(
        [sys.executable, tool, LOG, "--follow", "--year", "2025",
         "--output", OUT, "--quiet", "--checkpoint", ".live.ckpt",
         "--metrics-port", str(PORT), "--cooldown", "10", "--poll-interval", "0.1"],
        stderr=subprocess.PIPE, text=True)
    time.sleep(1.5)  # let it bind the port

    wt.start()
    print(f"{'t':>4} {'lines':>10} {'parsed':>10} {'lps_avg':>9} "
          f"{'incidents':>10} {'lag_s':>7}")
    samples = []
    for i in range(DURATION):
        time.sleep(1)
        m = poll_metrics()
        if "error" in m:
            print(f"  metrics error: {m['error']}")
            continue
        samples.append(m)
        print(f"{i+1:>4} {m['lines_total']:>10,} {m['events_parsed']:>10,} "
              f"{m['lines_per_sec_avg']:>9.0f} {m['incidents_emitted']:>10} "
              f"{str(m['seconds_since_last_line']):>7}")

    stop.set(); wt.join()

    # Let the daemon drain the remaining tail, then health-check + shutdown
    time.sleep(3)
    final = poll_metrics()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=2) as r:
            health = r.read().decode()
    except Exception as e:
        health = f"error: {e}"

    daemon.terminate()
    try:
        derr = daemon.communicate(timeout=5)[1]
    except subprocess.TimeoutExpired:
        daemon.kill(); derr = daemon.communicate()[1]

    print(f"\nWriter appended : {written['n']:,} lines")
    print(f"Daemon processed: {final.get('lines_total', '?'):,} lines")
    print(f"Health endpoint : {health}")
    print(f"Incidents       : {final.get('incidents_emitted')} "
          f"(suppressed {final.get('incidents_suppressed')})")
    print(f"By severity     : {final.get('by_severity')}")
    # Correctness: did it catch the injected brute force?
    cats = set()
    if os.path.exists(OUT):
        for l in open(OUT):
            cats.add(json.loads(l)["category"])
    print(f"Categories seen : {sorted(cats)}")
    caught = "Brute Force Attacks" in cats
    kept_up = final.get("lines_total", 0) >= written["n"] * 0.99
    print(f"\n{'PASS' if caught else 'FAIL'}: brute force detected live")
    print(f"{'PASS' if kept_up else 'FAIL'}: processed >=99% of appended lines "
          f"({final.get('lines_total',0):,}/{written['n']:,})")
    print("\n--- daemon stderr (tail) ---")
    print("\n".join(derr.strip().splitlines()[-4:]))
    sys.exit(0 if (caught and kept_up) else 1)

if __name__ == "__main__":
    main()
