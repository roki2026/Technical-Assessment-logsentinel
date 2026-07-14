#!/usr/bin/env python3
"""Coverage test: verify every user-required detection category actually fires."""
import json, os, subprocess, sys, tempfile

# Requirement -> (log content, expected category substring in output)
# Resolve the engine relative to the repo root, so this test works from anywhere.
TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "logsentinel.py")

CASES = {
 "Brute Force Attacks (SSH)": ("""Jul  3 10:00:01 s sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2
Jul  3 10:00:02 s sshd[1]: Failed password for root from 1.2.3.4 port 2 ssh2
Jul  3 10:00:03 s sshd[1]: Failed password for root from 1.2.3.4 port 3 ssh2
Jul  3 10:00:04 s sshd[1]: Failed password for root from 1.2.3.4 port 4 ssh2
Jul  3 10:00:05 s sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2
""", "Brute Force Attacks"),
 "web login brute force": ("""1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "POST /login HTTP/1.1" 401 1
1.2.3.4 - - [03/Jul/2025:10:00:02 +0000] "POST /login HTTP/1.1" 401 1
1.2.3.4 - - [03/Jul/2025:10:00:03 +0000] "POST /login HTTP/1.1" 401 1
1.2.3.4 - - [03/Jul/2025:10:00:04 +0000] "POST /login HTTP/1.1" 401 1
1.2.3.4 - - [03/Jul/2025:10:00:05 +0000] "POST /login HTTP/1.1" 401 1
""", "Brute Force Attacks"),
 "Unauthorized Access": ("""Jul  3 10:00:01 s sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2
Jul  3 10:00:02 s sshd[1]: Failed password for root from 1.2.3.4 port 2 ssh2
Jul  3 10:00:03 s sshd[1]: Failed password for root from 1.2.3.4 port 3 ssh2
Jul  3 10:00:04 s sshd[1]: Failed password for root from 1.2.3.4 port 4 ssh2
Jul  3 10:00:05 s sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2
Jul  3 10:00:06 s sshd[1]: Failed password for root from 1.2.3.4 port 6 ssh2
Jul  3 10:00:07 s sshd[1]: Accepted password for root from 1.2.3.4 port 7 ssh2
""", "compromise"),
 "Malware": ("""Jul  3 10:00:01 s kernel: powershell -enc SGVsbG8= detected on host
""", "Malware"),
 "Web Application Attacks (webshell)": ("""1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET /uploads/c99.php?cmd=ls HTTP/1.1" 200 1
""", "Malware"),
 "SQL injection": ("""1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET /s?q=' OR 1=1-- HTTP/1.1" 200 1
""", "SQL Injection"),
 "path traversal": ("""1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET /../../etc/passwd HTTP/1.1" 400 1
""", "Path Traversal"),
 "Network Attacks (port scan)": ("""Jul  3 10:00:01 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=21
Jul  3 10:00:02 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=22
Jul  3 10:00:03 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=23
Jul  3 10:00:04 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=25
Jul  3 10:00:05 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=53
Jul  3 10:00:06 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=80
Jul  3 10:00:07 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=110
Jul  3 10:00:08 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=143
Jul  3 10:00:09 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=443
Jul  3 10:00:10 s kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.1 DPT=3306
""", "Network Attacks"),
 "Reconnaissance": ("""1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1
""", "Reconnaissance"),
 "Data Breaches": ("""1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET /export/backup.sql HTTP/1.1" 200 90000000
""", "Data Breaches"),
 "rate-limit abuse": ("""1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "POST /api/x HTTP/1.1" 200 1
1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "POST /api/x HTTP/1.1" 429 1
""", "Rate-Limit Abuse"),
 "sudo misuse": ("""Jul  3 10:00:01 s sudo: eve : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash
""", "Sudo misuse"),
 "malformed line": ("""@@@ totally broken line ###
""", "malformed"),
 "cross-file correlation": (None, "Cross-File Correlation"),  # special: two files
 "Insider Threats": ("""Jul  3 03:00:01 s sshd[1]: Accepted password for bob from 10.0.0.9 port 1 ssh2
""", "Insider Threats"),
 "Persistence": ("""Jul  3 10:00:01 s useradd[1]: new user: name=evil, UID=0
""", "Persistence"),
 "Lateral Movement": ("""Jul  3 10:00:01 h1 sshd[1]: Accepted publickey for svc from 10.0.0.5 port 1 ssh2
Jul  3 10:00:02 h2 sshd[1]: Accepted publickey for svc from 10.0.0.5 port 2 ssh2
Jul  3 10:00:03 h3 sshd[1]: Accepted publickey for svc from 10.0.0.5 port 3 ssh2
""", "Lateral Movement"),
 "Command and Control (C2)": ("""5.5.5.5 - - [03/Jul/2025:10:00:00 +0000] "GET /cb HTTP/1.1" 200 1
5.5.5.5 - - [03/Jul/2025:10:00:30 +0000] "GET /cb HTTP/1.1" 200 1
5.5.5.5 - - [03/Jul/2025:10:01:00 +0000] "GET /cb HTTP/1.1" 200 1
5.5.5.5 - - [03/Jul/2025:10:01:30 +0000] "GET /cb HTTP/1.1" 200 1
5.5.5.5 - - [03/Jul/2025:10:02:00 +0000] "GET /cb HTTP/1.1" 200 1
5.5.5.5 - - [03/Jul/2025:10:02:30 +0000] "GET /cb HTTP/1.1" 200 1
""", "Command and Control (C2)"),
 "Credential Attacks": ("""Jul  3 10:00:01 s sudo: mal : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow
""", "Credential Attacks"),
 "Email Attacks": ("""Jul  3 10:00:01 mail postfix[1]: dmarc=fail phishing suspicious link from a@b.c
""", "Email Attacks"),
 "Supply Chain Attacks": ("""Jul  3 10:00:01 s pip[1]: package signature verification failed for requests-2.0
""", "Supply Chain Attacks"),
 "Cloud Security Incidents": ('{"eventTime":"2025-07-03T10:00:01Z","eventName":"StopLogging","sourceIPAddress":"1.2.3.4","userIdentity":{"userName":"a"}}\n',
                              "Cloud Security Incidents"),
 "Container & Kubernetes Attacks": ('{"eventTime":"2025-07-03T10:00:01Z","verb":"create","sourceIPs":["1.2.3.4"],"user":{"username":"d"},"objectRef":{"resource":"pods","subresource":"exec"},"msg":"pods/exec privileged: true"}\n',
                                    "Container & Kubernetes Attacks"),
 "IoT Attacks": ("""Jul  3 10:00:01 cam1 telnetd[1]: login attempt admin/admin default credential rejected
""", "IoT Attacks"),
 "Policy Violations": ("""Jul  3 10:00:01 s inetd[1]: telnetd started on port 23 cleartext password enabled
""", "Policy Violations"),
}

def run(paths):
    r = subprocess.run([sys.executable, TOOL, *paths,
                        "--year", "2025", "--no-color"],
                       capture_output=True, text=True)
    return r.stdout

def main():
    results, failed = [], []
    for name, (content, expect) in CASES.items():
        if content is None:  # cross-file correlation: same IP, 2 categories, 2 files
            f1 = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
            f1.write('9.9.9.9 - - [03/Jul/2025:10:00:01 +0000] "GET /a?q=\' OR 1=1-- HTTP/1.1" 200 1\n')
            f1.close()
            f2 = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
            f2.write("Jul  3 10:00:01 s useradd[1]: new user: name=evil, UID=0 by 9.9.9.9\n")
            f2.close()
            out = run([f1.name, f2.name])
            os.unlink(f1.name); os.unlink(f2.name)
        else:
            f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
            f.write(content); f.close()
            out = run([f.name])
            os.unlink(f.name)
        ok = expect.lower() in out.lower()
        results.append((name, ok, expect))
        if not ok:
            failed.append((name, expect, out))
    width = max(len(n) for n, _, _ in results)
    for name, ok, expect in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name.ljust(width)}  -> {expect}")
    print(f"\n{sum(ok for _, ok, _ in results)}/{len(results)} categories fire")
    for name, expect, out in failed:
        print(f"\n--- FAIL DETAIL: {name} (expected '{expect}') ---")
        print(out[-800:])
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
