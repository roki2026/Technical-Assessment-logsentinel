#!/usr/bin/env python3
"""
LogSentinel — a command-line security log analysis tool.

Parses one or more log files (syslog/auth.log, Apache/Nginx access logs,
JSON-lines e.g. CloudTrail / k8s audit, mail logs), applies configurable
detection rules, correlates activity across files, and reports potential
security incidents.

Usage:
    python3 logsentinel.py auth.log access.log cloudtrail.jsonl
    python3 logsentinel.py --rules rules.yaml --json report.json logs/*.log
"""

import argparse
import csv
import io
import json
import math
import os
import re
import signal
import statistics
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

try:
    import yaml
except ImportError:
    yaml = None

# --------------------------------------------------------------------------
# Normalized event model
# --------------------------------------------------------------------------

@dataclass
class Event:
    ts: datetime = None          # timestamp (may be None if unparseable)
    kind: str = "generic"        # syslog | web | json | mail | malformed
    src_ip: str = None
    user: str = None
    host: str = None
    process: str = None
    method: str = None           # web: HTTP method
    path: str = None             # web: request path
    status: int = None           # web: HTTP status
    size: int = None             # web: response bytes
    user_agent: str = None
    message: str = ""            # free-text portion / raw JSON summary
    extra: dict = field(default_factory=dict)
    file: str = ""
    lineno: int = 0
    raw: str = ""


@dataclass
class Incident:
    category: str
    severity: str                # critical | high | medium | low | info
    title: str
    description: str
    entities: dict               # {"ips": [...], "users": [...], "hosts": [...]}
    count: int
    first_seen: str
    last_seen: str
    evidence: list               # [(file, lineno, raw), ...] capped
    mitre: str = ""
    rule_id: str = ""

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
EVIDENCE_CAP = 8

# --------------------------------------------------------------------------
# Default configuration (embedded; overridable via --rules rules.yaml)
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "thresholds": {
        "brute_force":        {"count": 5,  "window_sec": 300},
        "web_login_brute":    {"count": 5,  "window_sec": 300},
        "web_login_success_min_fails": 3,
        "password_spray":     {"users": 5,  "window_sec": 600},
        "invalid_user_enum":  {"count": 3},
        "rate_limit":         {"requests": 60, "window_sec": 60},
        "recon_404":          {"count": 15, "window_sec": 300},
        "port_scan":          {"distinct_ports": 10, "window_sec": 120},
        "exfil_bytes":        50_000_000,
        "beacon_min_requests": 6,
        "beacon_max_jitter":   0.15,
        "off_hours":          {"start": 0, "end": 5},
        "cloud_login_failures": {"count": 5, "window_sec": 600},
        "observation_proximity_sec": 300,   # link window for analyst observations
    },
    "internal_networks": ["10.", "192.168.", "172.16.", "172.17.", "172.18."],
    "detectors": {  # enable/disable individual detectors
        "brute_force": True, "web_login_brute": True, "password_spray": True,
        "unauthorized_access": True, "sqli": True, "path_traversal": True,
        "rate_limit_abuse": True, "sudo_misuse": True, "malware": True,
        "recon": True, "port_scan": True, "exfiltration": True,
        "insider": True, "persistence": True, "lateral_movement": True,
        "c2": True, "credential_attacks": True, "email_attacks": True,
        "supply_chain": True, "cloud": True, "container_k8s": True,
        "iot": True, "policy": True, "malformed": True, "correlation": True,
        "observations": True,
    },
    # Generic pattern rules: applied to every event. field ∈ message|path|user_agent|process
    "pattern_rules": [
        {"id": "SQLI-001", "category": "SQL Injection", "severity": "high",
         "field": "path", "mitre": "T1190",
         "regex": r"(?i)(union[\s%20+]+select|['\"]\s*or\s+1\s*=\s*1|['\"]\s*or\s+['\"]?1['\"]?\s*=|;--|%27\s*or|sleep\(\d+\)|benchmark\(|information_schema|xp_cmdshell|;\s*(drop|delete|insert|update|select)\s|drop\s+table|delete\s+from)",
         "description": "SQL injection pattern in request path/query"},
        {"id": "TRAV-001", "category": "Path Traversal", "severity": "high",
         "field": "path", "mitre": "T1190",
         "regex": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e|/etc/passwd|/etc/shadow|c:\\windows)",
         "description": "Directory traversal attempt"},
        {"id": "MALW-001", "category": "Malware", "severity": "critical",
         "field": "message", "mitre": "T1059",
         "regex": r"(?i)(mimikatz|meterpreter|cobalt\s*strike|powershell.{0,40}-enc\b|certutil.{0,40}-urlcache|wget\s+http[^ ]+\s*\|\s*(sh|bash)|curl\s+[^|]+\|\s*(sh|bash)|base64\s+-d\s*\|\s*(sh|bash))",
         "description": "Malware / malicious tooling indicator"},
        {"id": "MALW-002", "category": "Malware", "severity": "high",
         "field": "path", "mitre": "T1105",
         "regex": r"(?i)(/(shell|c99|r57|webshell|cmd)\.(php|jsp|aspx?)|\.php\?cmd=|eval\(base64_decode)",
         "description": "Webshell upload/access attempt"},
        {"id": "RECON-001", "category": "Reconnaissance", "severity": "medium",
         "field": "user_agent", "mitre": "T1595",
         "regex": r"(?i)(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|acunetix|nessus|zgrab|hydra)",
         "description": "Known scanner user-agent"},
        {"id": "RECON-002", "category": "Reconnaissance", "severity": "medium",
         "field": "path", "mitre": "T1595",
         "regex": r"(?i)(/\.env\b|/\.git(/|\b)|/wp-config\.php|/phpinfo\.php|/\.aws/credentials|/id_rsa|/server-status|/actuator/env)",
         "description": "Probing for sensitive files/endpoints"},
        {"id": "PERS-001", "category": "Persistence", "severity": "high",
         "field": "message", "mitre": "T1136/T1053",
         "regex": r"(?i)(useradd|adduser|new user:|usermod\s+-aG\s+(sudo|wheel|admin)|crontab\s+-e|/etc/cron|systemctl\s+(enable|daemon-reload)|authorized_keys|\.bashrc\s+modified)",
         "description": "Persistence mechanism (account/cron/service/SSH key)"},
        {"id": "LAT-001", "category": "Lateral Movement", "severity": "high",
         "field": "message", "mitre": "T1021",
         "regex": r"(?i)(psexec|wmic\s+/node|winrm|smbclient\s+//|pass-the-hash|evil-winrm|xfreerdp|crackmapexec)",
         "description": "Lateral movement tooling"},
        {"id": "C2-001", "category": "Command and Control (C2)", "severity": "critical",
         "field": "message", "mitre": "T1071",
         "regex": r"(?i)(dns\s+tunnel|dnscat|beacon(ing)?\s+to|c2\s+server|/gate\.php|/panel/admin\.php|ngrok\.io|reverse\s+shell|connect-back)",
         "description": "Command-and-control indicator"},
        {"id": "CRED-001", "category": "Credential Attacks", "severity": "high",
         "field": "message", "mitre": "T1003",
         "regex": r"(?i)(kerberoast|asreproast|hashdump|lsass\s+dump|secretsdump|ntds\.dit|shadow\s+file\s+read|/etc/shadow.*(cat|cp|read))",
         "description": "Credential dumping / theft indicator"},
        {"id": "MAIL-001", "category": "Email Attacks", "severity": "medium",
         "field": "message", "mitre": "T1566",
         "regex": r"(?i)(phishing|malicious\s+attachment|spf\s+fail|dkim=fail|dmarc=fail|suspicious\s+link|attachment\s+blocked:.*\.(exe|js|vbs|scr))",
         "description": "Phishing / malicious email indicator"},
        {"id": "SUPPLY-001", "category": "Supply Chain Attacks", "severity": "high",
         "field": "message", "mitre": "T1195",
         "regex": r"(?i)(checksum\s+mismatch|signature\s+verification\s+failed|pip\s+install\s+.*--index-url\s+http:|npm\s+install\s+.*http:|typosquat|dependency\s+confusion|unsigned\s+package)",
         "description": "Suspicious package/dependency activity"},
        {"id": "CLOUD-001", "category": "Cloud Security Incidents", "severity": "critical",
         "field": "message", "mitre": "T1098/T1562",
         "regex": r"(PutBucketPolicy.*\"Principal\":\s*\"\*\"|PutBucketAcl.*public|DeleteTrail|StopLogging|CreateAccessKey|AttachUserPolicy.*AdministratorAccess|AuthorizeSecurityGroupIngress.*0\.0\.0\.0/0)",
         "description": "High-risk cloud control-plane action"},
        {"id": "K8S-001", "category": "Container & Kubernetes Attacks", "severity": "high",
         "field": "message", "mitre": "T1610/T1611",
         "regex": r"(?i)(pods/exec|privileged['\"]?\s*:\s*true|hostPID|hostNetwork['\"]?\s*:\s*true|docker\.sock|kubectl\s+create\s+clusterrolebinding.*cluster-admin|crictl\s+exec|/var/run/docker\.sock)",
         "description": "Container escape / risky Kubernetes action"},
        {"id": "IOT-001", "category": "IoT Attacks", "severity": "medium",
         "field": "message", "mitre": "T1078.001",
         "regex": r"(?i)(default\s+credential|login\s+attempt\s+(admin/admin|root/root|admin/1234)|mirai|busybox\s+(wget|tftp)|/bin/busybox\s+MIRAI|telnet\s+login\s+fail)",
         "description": "IoT default-credential / botnet activity"},
        {"id": "POL-001", "category": "Policy Violations", "severity": "low",
         "field": "message", "mitre": "-",
         "regex": r"(?i)(telnetd?\s+started|ftp\s+session\s+opened|cleartext\s+password|usb\s+storage\s+mounted|tor\s+(exit|relay|browser)|unauthorized\s+software\s+install)",
         "description": "Security policy violation (cleartext/legacy protocol, USB, Tor)"},
        {"id": "BREACH-001", "category": "Data Breaches", "severity": "critical",
         "field": "message", "mitre": "T1041",
         "regex": r"(?i)(mysqldump|pg_dump|mongodump|database\s+export|bulk\s+export|mass\s+download|scp\s+.*\.(sql|dump|tar\.gz)\s+.*@|/(export|dump|backup)/.*\.(sql|db|dump|bak))",
         "description": "Bulk data dump / exfiltration indicator"},
    ],
}

def deep_merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

def load_config(path):
    if not path:
        return DEFAULT_CONFIG
    if yaml is None:
        sys.exit("PyYAML is required for --rules (pip install pyyaml)")
    with open(path) as f:
        user_cfg = yaml.safe_load(f) or {}
    cfg = deep_merge(DEFAULT_CONFIG, user_cfg)
    # If user supplies pattern_rules, they extend defaults unless replace_rules: true
    if user_cfg.get("replace_rules"):
        cfg["pattern_rules"] = user_cfg.get("pattern_rules", [])
    elif "pattern_rules" in user_cfg:
        cfg["pattern_rules"] = DEFAULT_CONFIG["pattern_rules"] + user_cfg["pattern_rules"]
    return cfg

# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------

SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")

WEB_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>.*?)(?:\s+HTTP/[\d.]+)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
USER_RE = re.compile(r"(?:for(?: invalid user)?|user[= ])\s*([\w.-]+)")

def parse_syslog_ts(s, year):
    try:
        return datetime.strptime(f"{year} {s}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def parse_web_ts(s):
    try:
        return datetime.strptime(s.split()[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None

def parse_iso_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None

def parse_line(line, fname, lineno, year):
    line = line.rstrip("\n")
    if not line.strip():
        return None
    # JSON lines (CloudTrail, k8s audit, app logs)
    if line.lstrip().startswith("{"):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return Event(kind="malformed", raw=line, file=fname, lineno=lineno)
        msg = json.dumps(obj, separators=(",", ":"))
        ip = (obj.get("sourceIPAddress") or obj.get("sourceIPs", [None])[0]
              if isinstance(obj.get("sourceIPs"), list) else obj.get("sourceIPAddress")) \
              or obj.get("src_ip") or obj.get("ip")
        user = obj.get("user")
        if isinstance(user, dict):
            user = user.get("username")
        user = user or (obj.get("userIdentity") or {}).get("userName") \
                    or (obj.get("userIdentity") or {}).get("type")
        ts = parse_iso_ts(obj.get("eventTime") or obj.get("timestamp")
                          or obj.get("requestReceivedTimestamp") or obj.get("time"))
        ev = Event(ts=ts, kind="json", src_ip=ip, user=user,
                   message=msg, extra=obj, file=fname, lineno=lineno, raw=line)
        ev.extra["eventName"] = obj.get("eventName") or obj.get("verb")
        return ev
    # Web access log
    m = WEB_RE.match(line)
    if m:
        size = m.group("size")
        return Event(
            ts=parse_web_ts(m.group("ts")), kind="web",
            src_ip=m.group("ip"),
            user=None if m.group("user") == "-" else m.group("user"),
            method=m.group("method"), path=m.group("path"),
            status=int(m.group("status")),
            size=int(size) if size.isdigit() else 0,
            user_agent=m.group("ua") or "",
            message=f'{m.group("method")} {m.group("path")} {m.group("status")}',
            file=fname, lineno=lineno, raw=line)
    # Syslog
    m = SYSLOG_RE.match(line)
    if m:
        msg = m.group("msg")
        ipm = IP_RE.search(msg)
        um = USER_RE.search(msg)
        return Event(
            ts=parse_syslog_ts(m.group("ts"), year), kind="syslog",
            host=m.group("host"), process=m.group("proc"),
            src_ip=ipm.group(1) if ipm else None,
            user=um.group(1) if um else None,
            message=msg, file=fname, lineno=lineno, raw=line)
    return Event(kind="malformed", raw=line, file=fname, lineno=lineno)

# --------------------------------------------------------------------------
# Detection helpers
# --------------------------------------------------------------------------

def fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"

def make_incident(category, severity, title, desc, events, mitre="", rule_id=""):
    tss = sorted(e.ts for e in events if e.ts)
    ips = sorted({e.src_ip for e in events if e.src_ip})
    users = sorted({e.user for e in events if e.user})
    hosts = sorted({e.host for e in events if e.host})
    return Incident(
        category=category, severity=severity, title=title, description=desc,
        entities={"ips": ips, "users": users, "hosts": hosts},
        count=len(events),
        first_seen=fmt_ts(tss[0]) if tss else "unknown",
        last_seen=fmt_ts(tss[-1]) if tss else "unknown",
        evidence=[(e.file, e.lineno, e.raw[:220]) for e in events[:EVIDENCE_CAP]],
        mitre=mitre, rule_id=rule_id)

def sliding_window_hits(events, count, window_sec):
    """Return True-window subsets: does any window of `window_sec` contain >= count events?"""
    evs = sorted((e for e in events if e.ts), key=lambda e: e.ts)
    if len(evs) < count:
        return None
    for i in range(len(evs) - count + 1):
        if (evs[i + count - 1].ts - evs[i].ts).total_seconds() <= window_sec:
            return evs
    return None

def is_internal(ip, cfg):
    return ip and any(ip.startswith(p) for p in cfg["internal_networks"])

# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------

FAILED_SSH = re.compile(r"(?i)(failed password|authentication failure|invalid user)")
ACCEPTED_SSH = re.compile(r"(?i)accepted (password|publickey) for (\S+)")
LOGIN_PATH = re.compile(r"(?i)/(login|signin|wp-login\.php|admin/login|api/auth|session)")

def detect_pattern_rules(events, cfg, incidents):
    """Generic regex rules from config (the core of configurability)."""
    compiled = []
    for r in cfg["pattern_rules"]:
        try:
            compiled.append((r, re.compile(r["regex"])))
        except re.error as exc:
            print(f"[!] Skipping invalid rule {r.get('id')}: {exc}", file=sys.stderr)
    hits = defaultdict(list)
    for e in events:
        for rule, rx in compiled:
            val = getattr(e, rule.get("field", "message"), None) or ""
            if rx.search(val):
                hits[rule["id"]].append(e)
    for rule, _ in compiled:
        evs = hits.get(rule["id"])
        if evs:
            ips = {e.src_ip for e in evs if e.src_ip}
            incidents.append(make_incident(
                rule["category"], rule["severity"],
                f'{rule["description"]} ({len(evs)} event(s))',
                f'Rule {rule["id"]} matched on field "{rule.get("field","message")}". '
                f'Sources: {", ".join(sorted(ips)) or "n/a"}.',
                evs, mitre=rule.get("mitre", ""), rule_id=rule["id"]))

def detect_brute_force(events, cfg, incidents):
    th = cfg["thresholds"]["brute_force"]
    min_fails = cfg["thresholds"]["web_login_success_min_fails"]
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "syslog" and e.src_ip and FAILED_SSH.search(e.message):
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.ts or datetime.min)
        # Success from the same IP after failures = compromise. Fires even below
        # the volume threshold — "some failures then a success" beats raw count.
        succ = [e for e in events if e.src_ip == ip and e.ts and evs
                and e.ts >= evs[0].ts and ACCEPTED_SSH.search(e.message or "")]
        if len(evs) >= min_fails and succ:
            m = ACCEPTED_SSH.search(succ[0].message)
            user = m.group(2) if m else "unknown"
            incidents.append(make_incident(
                "Brute Force Attacks", "critical",
                f"SSH brute force from {ip} SUCCEEDED "
                f"({len(evs)} failures then login as '{user}')",
                f"{len(evs)} failed SSH authentications followed by an accepted "
                f"login as '{user}' from the same IP. Treat the account as "
                "compromised.", evs + succ[:1], mitre="T1110/T1078"))
            continue
        hit = sliding_window_hits(evs, th["count"], th["window_sec"])
        if hit:
            users = {e.user for e in hit if e.user}
            incidents.append(make_incident(
                "Brute Force Attacks", "high",
                f"SSH brute force from {ip} ({len(hit)} failed attempts)",
                f"{len(hit)} failed authentications within {th['window_sec']}s "
                f"targeting user(s): {', '.join(sorted(users)) or 'unknown'}.",
                hit, mitre="T1110"))
            # Compromise check: success from same IP after the failures
            last_fail = max(e.ts for e in hit if e.ts)
            for e in events:
                if (e.src_ip == ip and e.ts and e.ts >= last_fail
                        and ACCEPTED_SSH.search(e.message or "")):
                    incidents.append(make_incident(
                        "Unauthorized Access", "critical",
                        f"Successful login from {ip} AFTER brute force — likely compromise",
                        "An accepted authentication followed a brute-force burst from the "
                        "same source IP. Treat the account as compromised.",
                        [e], mitre="T1078"))
                    break

def detect_web_login_brute(events, cfg, incidents):
    th = cfg["thresholds"]["web_login_brute"]
    min_fails = cfg["thresholds"]["web_login_success_min_fails"]
    fails_by_ip = defaultdict(list)
    for e in events:
        if (e.kind == "web" and e.path and LOGIN_PATH.search(e.path)
                and e.status in (401, 403) and e.method == "POST"):
            fails_by_ip[e.src_ip].append(e)
    for ip, evs in fails_by_ip.items():
        evs.sort(key=lambda e: e.ts or datetime.min)
        # Success on the same login endpoint after the failures = compromise.
        # This fires even below the pure brute-force threshold, because
        # "several failures then a success" is a stronger signal than volume.
        ok = [e for e in events if e.kind == "web" and e.src_ip == ip
              and e.path and LOGIN_PATH.search(e.path) and e.status == 200
              and e.ts and evs and e.ts >= evs[0].ts]
        if len(evs) >= min_fails and ok:
            incidents.append(make_incident(
                "Brute Force Attacks", "critical",
                f"Login brute force from {ip} SUCCEEDED "
                f"({len(evs)} failures then a successful login)",
                f"{len(evs)} failed login POSTs followed by HTTP 200 on the same "
                f"endpoint {sorted({e.path for e in evs})} — probable account "
                "takeover. Treat the account as compromised.",
                evs + ok[:1], mitre="T1110.001/T1078"))
            continue  # already the most severe finding for this IP
        # Otherwise, pure high-volume brute force without observed success.
        hit = sliding_window_hits(evs, th["count"], th["window_sec"])
        if hit:
            incidents.append(make_incident(
                "Brute Force Attacks", "high",
                f"Web login brute force from {ip} ({len(hit)} failed POSTs)",
                f"Repeated failed login POSTs within {th['window_sec']}s against "
                f"{sorted({e.path for e in hit})}.", hit, mitre="T1110.001"))

def detect_password_spray(events, cfg, incidents):
    th = cfg["thresholds"]["password_spray"]
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "syslog" and e.src_ip and e.user and FAILED_SSH.search(e.message):
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        users = {e.user for e in evs}
        if len(users) >= th["users"]:
            incidents.append(make_incident(
                "Credential Attacks", "high",
                f"Password spraying from {ip} across {len(users)} accounts",
                f"One source attempted many distinct usernames "
                f"({', '.join(sorted(users)[:8])}…). Classic low-and-slow spray.",
                evs, mitre="T1110.003"))

INVALID_USER_RE = re.compile(r"(?i)invalid user (\S+)")
def detect_invalid_user_enum(events, cfg, incidents):
    """Low-volume SSH username enumeration: several 'invalid user' failures from
    one IP. Catches probing that stays under the brute-force volume threshold."""
    n = cfg["thresholds"]["invalid_user_enum"]["count"]
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "syslog" and e.src_ip and INVALID_USER_RE.search(e.message or ""):
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        # skip if this IP already produced a brute/compromise incident
        if any(ip in inc.entities.get("ips", []) and inc.category == "Brute Force Attacks"
               for inc in incidents):
            continue
        users = {INVALID_USER_RE.search(e.message).group(1) for e in evs}
        if len(evs) >= n:
            incidents.append(make_incident(
                "Reconnaissance", "medium",
                f"SSH username enumeration from {ip} "
                f"({len(evs)} attempts on invalid accounts)",
                f"Login attempts against non-existent users "
                f"({', '.join(sorted(users)[:8])}) — probing valid usernames, "
                "typical of a pre-brute-force sweep.", evs, mitre="T1589.001"))

def detect_rate_abuse(events, cfg, incidents):
    th = cfg["thresholds"]["rate_limit"]
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "web" and e.src_ip:
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        hit = sliding_window_hits(evs, th["requests"], th["window_sec"])
        if hit:
            incidents.append(make_incident(
                "Network Attacks", "medium",
                f"Rate-limit abuse: {ip} sent ≥{th['requests']} requests in {th['window_sec']}s",
                "Request rate far above normal — possible DoS, scraping, or enumeration.",
                hit, mitre="T1498"))
            continue
        # Server-enforced signal: the application itself returned 429 to this IP.
        # Trust the server's own judgment even below our volume threshold.
        throttled = [e for e in evs if e.status == 429]
        if throttled:
            burst = [e for e in evs
                     if e.path in {t.path for t in throttled}] or throttled
            incidents.append(make_incident(
                "Rate-Limit Abuse", "medium",
                f"Server throttled {ip} with HTTP 429 "
                f"({len(burst)} rapid requests to {sorted({e.path for e in throttled})})",
                "The application returned 429 Too Many Requests — automated/scripted "
                "activity (e.g. mass account creation or API hammering) confirmed by "
                "the server's own rate limiter.", burst, mitre="T1498"))

def detect_recon_404(events, cfg, incidents):
    th = cfg["thresholds"]["recon_404"]
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "web" and e.status == 404:
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        hit = sliding_window_hits(evs, th["count"], th["window_sec"])
        if hit and len({e.path for e in hit}) >= th["count"] // 2:
            incidents.append(make_incident(
                "Reconnaissance", "medium",
                f"Forced-browsing / directory enumeration from {ip}",
                f"{len(hit)} 404s across {len({e.path for e in hit})} distinct paths "
                f"within {th['window_sec']}s.", hit, mitre="T1595.003"))

SCAN_PATH_RE = re.compile(
    r"(?i)/(admin|administrator|phpmyadmin|wp-admin|wp-login|manager|"
    r"\.env|\.git|config\.php|cgi-bin|xmlrpc\.php|solr|jenkins|"
    r"actuator|server-status|\.aws|\.ssh)")

def detect_vuln_scan(events, cfg, incidents):
    """Group probes of admin/sensitive paths (any 403/404) into one scan incident.
    Catches vulnerability scanners even below the raw-404 enumeration threshold."""
    th = cfg["thresholds"]["recon_404"]
    by_ip = defaultdict(list)
    for e in events:
        if (e.kind == "web" and e.path and e.status in (400, 401, 403, 404)
                and SCAN_PATH_RE.search(e.path)):
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        paths = {e.path for e in evs}
        if len(paths) >= 4:  # several distinct sensitive endpoints = scanning
            incidents.append(make_incident(
                "Reconnaissance", "high",
                f"Vulnerability scan from {ip} "
                f"({len(paths)} admin/sensitive endpoints probed)",
                f"Probed sensitive paths: {', '.join(sorted(paths)[:10])}. "
                "Consistent with automated vulnerability/CMS scanning.",
                evs, mitre="T1595.003"))

PORT_RE = re.compile(r"DPT=(\d+)")
def detect_port_scan(events, cfg, incidents):
    th = cfg["thresholds"]["port_scan"]
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "syslog" and e.src_ip and "DPT=" in e.message:
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        ports = {PORT_RE.search(e.message).group(1) for e in evs if PORT_RE.search(e.message)}
        if len(ports) >= th["distinct_ports"]:
            incidents.append(make_incident(
                "Network Attacks", "medium",
                f"Port scan from {ip} ({len(ports)} distinct ports probed)",
                f"Firewall logged connection attempts to ports: "
                f"{', '.join(sorted(ports, key=int)[:15])}…", evs, mitre="T1046"))

SUDO_USER_RE = re.compile(r"^\s*(\w[\w.-]*)\s*:")
SUDO_CMD_RE = re.compile(r"COMMAND=(.+)$")
# Sensitive commands that, run via sudo, indicate credential access or tampering.
SENSITIVE_SUDO_RE = re.compile(
    r"(?i)(/etc/shadow|/etc/gshadow|/etc/sudoers|/root/\.ssh|"
    r"\.ssh/(id_rsa|authorized_keys)|/etc/passwd.*(vi|nano|>)|"
    r"(cat|less|more|cp|scp|vi|nano|head|tail|strings)\s+[^\n]*"
    r"(/etc/shadow|/etc/sudoers|id_rsa)|mysqldump|tcpdump|nc\s+-|nmap)")

def detect_sudo_misuse(events, cfg, incidents):
    bad, sensitive = [], []
    for e in events:
        if not (e.kind == "syslog" and e.process and e.process.startswith("sudo")):
            continue
        um = SUDO_USER_RE.match(e.message)
        if um:
            e.user = um.group(1)          # invoking user (before first colon)
        if re.search(r"(?i)(NOT in sudoers|incorrect password attempts|"
                     r"command not allowed|3 incorrect)", e.message):
            bad.append(e)
        else:
            cm = SUDO_CMD_RE.search(e.message)
            cmd = cm.group(1) if cm else ""
            if cmd and SENSITIVE_SUDO_RE.search(cmd):
                sensitive.append(e)
    if bad:
        users = sorted({e.user for e in bad if e.user})
        incidents.append(make_incident(
            "Policy Violations", "medium",
            f"Sudo misuse: {len(bad)} unauthorized privilege-escalation attempts",
            f"Users attempting sudo without authorization: "
            f"{', '.join(users) or 'unknown'}.",
            bad, mitre="T1548.003"))
    if sensitive:
        for e in sensitive:
            cmd = SUDO_CMD_RE.search(e.message).group(1)
            incidents.append(make_incident(
                "Credential Attacks", "high",
                f"Sensitive sudo command by '{e.user}': {cmd[:80]}",
                "A successful sudo executed a command that reads credentials or "
                "alters privilege configuration (e.g. shadow/sudoers/SSH keys). "
                "Verify this was authorized.", [e], mitre="T1003.008"))

def detect_exfil(events, cfg, incidents):
    limit = cfg["thresholds"]["exfil_bytes"]
    big = [e for e in events if e.kind == "web" and (e.size or 0) >= limit
           and (e.method in ("GET", "POST"))]
    by_ip = defaultdict(list)
    for e in big:
        by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        total = sum(e.size for e in evs)
        incidents.append(make_incident(
            "Data Breaches", "critical",
            f"Possible data exfiltration to {ip} ({total/1e6:.0f} MB transferred)",
            f"Unusually large responses served: "
            f"{', '.join(sorted({e.path for e in evs})[:5])}.", evs, mitre="T1041"))

def detect_insider(events, cfg, incidents):
    th = cfg["thresholds"]["off_hours"]
    offs = []
    for e in events:
        if (e.kind == "syslog" and e.ts and th["start"] <= e.ts.hour < th["end"]
                and ACCEPTED_SSH.search(e.message or "")
                and is_internal(e.src_ip, cfg)):
            offs.append(e)
    if offs:
        incidents.append(make_incident(
            "Insider Threats", "low",
            f"Off-hours internal logins ({len(offs)} between "
            f"{th['start']:02d}:00–{th['end']:02d}:00)",
            "Successful logins from internal addresses outside business hours. "
            "Verify with the account owners.", offs, mitre="T1078"))

def detect_lateral(events, cfg, incidents):
    hops = defaultdict(list)
    for e in events:
        m = ACCEPTED_SSH.search(e.message or "") if e.kind == "syslog" else None
        if m and is_internal(e.src_ip, cfg):
            hops[m.group(2)].append(e)
    for user, evs in hops.items():
        hosts = {e.host for e in evs if e.host}
        if len(hosts) >= 3:
            incidents.append(make_incident(
                "Lateral Movement", "high",
                f"Account '{user}' hopped across {len(hosts)} internal hosts",
                f"Internal SSH logins to: {', '.join(sorted(hosts))}. "
                "Sequential multi-host access is a lateral-movement pattern.",
                evs, mitre="T1021.004"))

def detect_beaconing(events, cfg, incidents):
    minreq = cfg["thresholds"]["beacon_min_requests"]
    jitter = cfg["thresholds"]["beacon_max_jitter"]
    by_key = defaultdict(list)
    for e in events:
        if e.kind == "web" and e.ts and e.src_ip and e.path:
            by_key[(e.src_ip, e.path)].append(e)
    for (ip, path), evs in by_key.items():
        if len(evs) < minreq:
            continue
        evs.sort(key=lambda e: e.ts)
        gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(evs, evs[1:])]
        if not gaps or min(gaps) < 5:
            continue
        mean = statistics.mean(gaps)
        stdev = statistics.pstdev(gaps)
        if mean >= 10 and (stdev / mean) <= jitter:
            incidents.append(make_incident(
                "Command and Control (C2)", "critical",
                f"Beaconing: {ip} → {path} every ~{mean:.0f}s ({len(evs)} requests)",
                f"Highly regular interval (jitter {stdev/mean:.1%}) — characteristic "
                "of C2 check-ins rather than human browsing.", evs, mitre="T1071.001"))

CLOUD_FAIL = re.compile(r'"ConsoleLogin".*"Failure"|"errorMessage":"Failed authentication"')
def detect_cloud_login(events, cfg, incidents):
    th = cfg["thresholds"]["cloud_login_failures"]
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "json" and CLOUD_FAIL.search(e.message):
            by_ip[e.src_ip or "unknown"].append(e)
    for ip, evs in by_ip.items():
        if len(evs) >= th["count"]:
            incidents.append(make_incident(
                "Cloud Security Incidents", "high",
                f"Cloud console brute force from {ip} ({len(evs)} failed logins)",
                "Repeated failed ConsoleLogin events in cloud audit trail.",
                evs, mitre="T1110"))

def detect_malformed(events, cfg, incidents):
    bad = [e for e in events if e.kind == "malformed"]
    if bad:
        files = sorted({e.file for e in bad})
        incidents.append(make_incident(
            "Data Quality", "info",
            f"{len(bad)} malformed / unparseable line(s)",
            f"Lines that matched no known format in: {', '.join(files)}. "
            "Could indicate log tampering, corruption, or an unsupported format.",
            bad))

KILL_CHAIN = ["Reconnaissance", "Brute Force Attacks", "Credential Attacks",
              "SQL Injection", "Path Traversal", "Unauthorized Access", "Malware",
              "Persistence", "Lateral Movement", "Command and Control (C2)",
              "Data Breaches"]

def detect_correlation(events, cfg, incidents):
    """Cross-file / cross-category correlation: same IP in multiple attack stages."""
    by_ip = defaultdict(lambda: {"cats": set(), "files": set(),
                                 "incidents": [], "first": [], "last": []})
    for inc in incidents:
        if inc.severity == "info":
            continue
        for ip in inc.entities.get("ips", []):
            by_ip[ip]["cats"].add(inc.category)
            by_ip[ip]["files"].update(f for f, _, _ in inc.evidence)
            by_ip[ip]["incidents"].append(inc)
            if inc.first_seen != "unknown":
                by_ip[ip]["first"].append(inc.first_seen)
            if inc.last_seen != "unknown":
                by_ip[ip]["last"].append(inc.last_seen)
    new = []
    for ip, d in by_ip.items():
        multi_stage = len(d["cats"]) >= 2 and len(d["files"]) >= 2
        # Same-category across services also correlates: e.g. one IP brute-forcing
        # both SSH and the web login is one coordinated attack, not two alerts.
        multi_service = len(d["incidents"]) >= 2 and len(d["files"]) >= 2
        if multi_stage or multi_service:
            chain = [c for c in KILL_CHAIN if c in d["cats"]] or sorted(d["cats"])
            title = (f"Multi-stage attack from {ip}: {' → '.join(chain)}"
                     if multi_stage else
                     f"Coordinated multi-service attack from {ip} "
                     f"({chain[0]} against {len(d['files'])} services)")
            evs = [Event(file=f, lineno=l, raw=r)
                   for inc in d["incidents"] for f, l, r in inc.evidence[:2]]
            inc = make_incident(
                "Cross-File Correlation", "critical",
                title,
                f"IP {ip} appears in {len(d['incidents'])} separate detections across "
                f"{len(d['files'])} log files ({', '.join(sorted(d['files']))}). "
                "Coordinated activity spanning multiple attack stages.",
                evs, mitre="multiple")
            inc.entities["ips"] = [ip]
            if d["first"]:
                inc.first_seen = min(d["first"])
            if d["last"]:
                inc.last_seen = max(d["last"])
            new.append(inc)
    incidents.extend(new)

# --------------------------------------------------------------------------
# Analyst observations — context worth a human's eye, deliberately NOT alerts.
# These are speculative linkages/anomalies; they are reported in a separate
# section, excluded from severity counts, and never affect the exit code.
# --------------------------------------------------------------------------

COMPROMISE_CATS = {"Brute Force Attacks", "Unauthorized Access"}
FOLLOWUP_CATS = {"Credential Attacks", "Persistence", "Data Breaches",
                 "Lateral Movement"}
PORT_IN_MSG = re.compile(r"\bport (\d+)\b")
PREAUTH_CLOSE = re.compile(r"(?i)connection closed by ([\d.]+) port (\d+)\s*\[preauth\]")

def _parse_seen(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None

def detect_observations(events, cfg, incidents, observations):
    window = cfg["thresholds"]["observation_proximity_sec"]

    # 1) Temporal proximity: a credential/persistence/exfil action by a
    #    DIFFERENT identity shortly after a confirmed compromise. Classic
    #    post-exploitation sequence — but linkage is unproven, so it's a note.
    compromises = [i for i in incidents
                   if i.category in COMPROMISE_CATS and i.severity == "critical"]
    followups = [i for i in incidents if i.category in FOLLOWUP_CATS]
    seen_pairs = set()
    for c in compromises:
        c_ts = _parse_seen(c.last_seen)
        if not c_ts:
            continue
        for f in followups:
            f_ts = _parse_seen(f.first_seen)
            if not f_ts:
                continue
            key = (f.title, tuple(sorted(c.entities.get("ips", []))))
            delta = (f_ts - c_ts).total_seconds()
            if 0 <= delta <= window and key not in seen_pairs and \
               set(f.entities.get("users", [])) - set(c.entities.get("users", [])):
                seen_pairs.add(key)
                observations.append(make_incident(
                    "Analyst Observation", "note",
                    f"'{f.title[:70]}' occurred {delta:.0f}s after a confirmed "
                    f"compromise from {', '.join(c.entities.get('ips', ['?']))}",
                    "Timeline proximity between a compromise and a subsequent "
                    "sensitive action by a different identity. This matches the "
                    "classic post-exploitation sequence (initial access → "
                    "credential access), but the logs do not prove the two are "
                    "connected. Recommend investigating whether the identities "
                    "are linked.",
                    [Event(file=fl, lineno=ln, raw=raw)
                     for fl, ln, raw in (c.evidence[-1:] + f.evidence[:1])]))

    # 2) Session inconsistency: a '[preauth]' connection close on an IP:port
    #    pair that previously produced an ACCEPTED login. A source port can't
    #    both authenticate and close pre-auth — log artifact or tampering.
    accepted_ports = {}
    for e in events:
        if e.kind == "syslog" and e.src_ip and ACCEPTED_SSH.search(e.message or ""):
            pm = PORT_IN_MSG.search(e.message)
            if pm:
                accepted_ports[(e.src_ip, pm.group(1))] = e
    for e in events:
        if e.kind != "syslog":
            continue
        m = PREAUTH_CLOSE.search(e.message or "")
        if m and (m.group(1), m.group(2)) in accepted_ports:
            acc = accepted_ports[(m.group(1), m.group(2))]
            observations.append(make_incident(
                "Analyst Observation", "note",
                f"Session inconsistency: {m.group(1)}:{m.group(2)} closed "
                f"'[preauth]' but the same port previously authenticated",
                "A '[preauth]' close means the connection ended before "
                "authentication, yet this exact source IP:port pair produced an "
                "accepted login earlier. The line parses cleanly, so it is not "
                "flagged as malformed — but it is semantically contradictory. "
                "Possible log artifact, clock/ordering issue, or tampering. "
                "Recommend comparing against a second log source.",
                [acc, e]))

DETECTOR_MAP = {
    "brute_force": detect_brute_force,
    "web_login_brute": detect_web_login_brute,
    "password_spray": detect_password_spray,
    "invalid_user_enum": detect_invalid_user_enum,
    "rate_limit_abuse": detect_rate_abuse,
    "recon": detect_recon_404,
    "vuln_scan": detect_vuln_scan,
    "port_scan": detect_port_scan,
    "sudo_misuse": detect_sudo_misuse,
    "exfiltration": detect_exfil,
    "insider": detect_insider,
    "lateral_movement": detect_lateral,
    "c2": detect_beaconing,
    "cloud": detect_cloud_login,
    "malformed": detect_malformed,
}

# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

COLORS = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m",
          "low": "\033[94m", "info": "\033[90m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"

def colorize(use_color):
    if use_color:
        return COLORS, RESET, BOLD, DIM
    return defaultdict(str), "", "", ""

def print_report(incidents, stats, use_color, observations=None):
    observations = observations or []
    C, R, B, D = colorize(use_color)
    incidents.sort(key=lambda i: (SEV_ORDER.get(i.severity, 9), i.category))
    print(f"\n{B}{'='*74}{R}")
    print(f"{B} LOGSENTINEL SECURITY REPORT{R}")
    print(f"{B}{'='*74}{R}")
    print(f" Files analyzed : {stats['files']}   Lines: {stats['lines']:,}   "
          f"Parsed: {stats['parsed']:,}   Malformed: {stats['malformed']:,}")
    print(f" Incidents      : {len(incidents)}")
    counts = defaultdict(int)
    for i in incidents:
        counts[i.severity] += 1
    print(" By severity    : " + "  ".join(
        f"{C[s]}{s.upper()}: {counts[s]}{R}" for s in SEV_ORDER if counts[s]))
    print(f"{B}{'-'*74}{R}")
    for n, inc in enumerate(incidents, 1):
        print(f"\n{C[inc.severity]}[{n}] [{inc.severity.upper():8}] "
              f"{inc.category}{R}")
        print(f"    {B}{inc.title}{R}")
        print(f"    {inc.description}")
        meta = []
        if inc.entities.get("ips"):
            meta.append("IPs: " + ", ".join(inc.entities["ips"][:6]))
        if inc.entities.get("users"):
            meta.append("Users: " + ", ".join(inc.entities["users"][:6]))
        if inc.mitre and inc.mitre != "-":
            meta.append(f"MITRE ATT&CK: {inc.mitre}")
        print(f"    {D}{' | '.join(meta)}{R}" if meta else "", end="")
        if meta:
            print()
        print(f"    {D}Window: {inc.first_seen} → {inc.last_seen}  "
              f"({inc.count} events){R}")
        for f, ln, raw in inc.evidence[:3]:
            print(f"      {D}↳ {f}:{ln}  {raw[:110]}{R}")
        if inc.count > 3:
            print(f"      {D}… {inc.count - 3} more (see JSON report for full evidence){R}")
    if observations:
        print(f"\n{B}{'-'*74}{R}")
        print(f"{B} ANALYST OBSERVATIONS — context for human review, not alerts.{R}")
        print(f"{D} Speculative linkages/anomalies. Not counted in severity totals"
              f" and do not affect the exit code.{R}")
        for n, ob in enumerate(observations, 1):
            print(f"\n{D}[N{n}]{R} {B}{ob.title}{R}")
            print(f"    {ob.description}")
            for f, ln, raw in ob.evidence[:3]:
                print(f"      {D}↳ {f}:{ln}  {raw[:110]}{R}")
    print(f"\n{B}{'='*74}{R}\n")

def write_json(incidents, stats, path, observations=None):
    doc = {"generated": datetime.now(timezone.utc).isoformat(),
           "stats": stats,
           "incidents": [vars(i) for i in incidents],
           "analyst_observations": [vars(o) for o in (observations or [])]}
    with open(path, "w") as f:
        json.dump(doc, f, indent=2, default=str)

def write_csv(incidents, path, observations=None):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["severity", "category", "title", "count",
                    "first_seen", "last_seen", "ips", "users", "mitre", "rule_id"])
        for i in incidents:
            w.writerow([i.severity, i.category, i.title, i.count, i.first_seen,
                        i.last_seen, ";".join(i.entities.get("ips", [])),
                        ";".join(i.entities.get("users", [])), i.mitre, i.rule_id])
        for o in (observations or []):
            w.writerow(["note", o.category, o.title, o.count, o.first_seen,
                        o.last_seen, ";".join(o.entities.get("ips", [])),
                        ";".join(o.entities.get("users", [])), "", ""])

# --------------------------------------------------------------------------
# Metrics / health endpoint (optional, --metrics-port)
# --------------------------------------------------------------------------

class Metrics:
    """Thread-safe counters exposed over HTTP as JSON and Prometheus text."""
    def __init__(self):
        import threading
        self._lock = threading.Lock()
        self.start_ts = time.time()
        self.lines_total = 0
        self.events_parsed = 0
        self.malformed = 0
        self.incidents_emitted = 0
        self.incidents_suppressed = 0
        self.by_severity = defaultdict(int)
        self.by_category = defaultdict(int)
        self.last_event_ts = None
        self.last_line_wall = None
        self.files = 0
        self.shard = None

    def inc_line(self, parsed):
        with self._lock:
            self.lines_total += 1
            if parsed:
                self.events_parsed += 1
            self.last_line_wall = time.time()

    def inc_malformed(self):
        with self._lock:
            self.malformed += 1

    def inc_incident(self, severity, category):
        with self._lock:
            self.incidents_emitted += 1
            self.by_severity[severity] += 1
            self.by_category[category] += 1

    def inc_suppressed(self):
        with self._lock:
            self.incidents_suppressed += 1

    def set_event_ts(self, ts):
        if ts:
            with self._lock:
                self.last_event_ts = ts.isoformat()

    def snapshot(self):
        with self._lock:
            uptime = time.time() - self.start_ts
            rate = self.lines_total / uptime if uptime > 0 else 0
            idle = (time.time() - self.last_line_wall) if self.last_line_wall else None
            return {
                "status": "ok",
                "uptime_sec": round(uptime, 1),
                "lines_total": self.lines_total,
                "events_parsed": self.events_parsed,
                "malformed": self.malformed,
                "lines_per_sec_avg": round(rate, 1),
                "incidents_emitted": self.incidents_emitted,
                "incidents_suppressed": self.incidents_suppressed,
                "by_severity": dict(self.by_severity),
                "by_category": dict(self.by_category),
                "last_event_time": self.last_event_ts,
                "seconds_since_last_line": round(idle, 1) if idle is not None else None,
                "files_followed": self.files,
                "shard": (f"{self.shard[0]}/{self.shard[1]}" if self.shard else None),
            }

    def prometheus(self):
        s = self.snapshot()
        lines = [
            "# HELP logsentinel_lines_total Log lines processed",
            "# TYPE logsentinel_lines_total counter",
            f"logsentinel_lines_total {s['lines_total']}",
            "# HELP logsentinel_incidents_total Incidents emitted",
            "# TYPE logsentinel_incidents_total counter",
            f"logsentinel_incidents_total {s['incidents_emitted']}",
            "# HELP logsentinel_incidents_suppressed_total Alerts suppressed by cooldown",
            "# TYPE logsentinel_incidents_suppressed_total counter",
            f"logsentinel_incidents_suppressed_total {s['incidents_suppressed']}",
            "# HELP logsentinel_malformed_total Unparseable lines",
            "# TYPE logsentinel_malformed_total counter",
            f"logsentinel_malformed_total {s['malformed']}",
            "# HELP logsentinel_lines_per_sec Average processing rate",
            "# TYPE logsentinel_lines_per_sec gauge",
            f"logsentinel_lines_per_sec {s['lines_per_sec_avg']}",
            "# HELP logsentinel_uptime_seconds Daemon uptime",
            "# TYPE logsentinel_uptime_seconds gauge",
            f"logsentinel_uptime_seconds {s['uptime_sec']}",
        ]
        for sev, n in s["by_severity"].items():
            lines.append(f'logsentinel_incidents_by_severity{{severity="{sev}"}} {n}')
        return "\n".join(lines) + "\n"


def start_metrics_server(metrics, port):
    """Launch a daemon HTTP thread serving /health, /metrics, /metrics/prometheus."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path in ("/health", "/healthz", "/"):
                body, ctype = b'{"status":"ok"}', "application/json"
            elif self.path == "/metrics":
                body = json.dumps(metrics.snapshot(), indent=2).encode()
                ctype = "application/json"
            elif self.path == "/metrics/prometheus":
                body = metrics.prometheus().encode()
                ctype = "text/plain; version=0.0.4"
            else:
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    try:
        srv = HTTPServer(("0.0.0.0", port), Handler)
    except OSError as e:
        print(f"[!] Metrics server failed to bind :{port}: {e}", file=sys.stderr)
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[*] Metrics: http://0.0.0.0:{port}/metrics "
          f"(also /health, /metrics/prometheus)", file=sys.stderr)
    return srv


# --------------------------------------------------------------------------
# STREAMING ENGINE (--follow): continuous, bounded-memory processing.
#
# Design principles:
#   * Events are processed one at a time and immediately discarded — memory
#     stays flat regardless of volume.
#   * Every stateful detector keeps only small, time-evicted, size-capped
#     per-entity aggregates (deques/sets), never full event lists.
#   * Incidents are emitted as JSON-lines the moment they fire, with a
#     per-(detector, entity) cooldown so a 10k-line brute force produces a
#     handful of alerts (with occurrence counts), not 10k.
#   * File positions are checkpointed (inode-aware, rotation/truncation safe)
#     so restarts neither lose lines nor re-alert on old ones.
# --------------------------------------------------------------------------

STREAM_TTL_SEC = 3600          # forget per-entity state after 1h inactivity
STREAM_MAX_KEYS = 50_000       # hard cap per state table (drop oldest)
BEACON_MAX_KEYS = 5_000

class StreamState:
    """All mutable detector state. Everything here is bounded."""
    def __init__(self):
        dq = lambda: deque(maxlen=200)
        self.ssh_fails = {}        # ip -> deque[event ts]
        self.web_fails = {}        # ip -> deque[event ts]
        self.ssh_users = {}        # ip -> set(usernames) (spray)
        self.invalid_users = {}    # ip -> set(usernames) (enumeration)
        self.ports = {}            # ip -> set(ports)
        self.rate = {}             # ip -> deque[event ts]
        self.notfound = {}         # ip -> deque[(ts, path)]
        self.scanpaths = {}        # ip -> set(sensitive paths)
        self.beacons = {}          # (ip, path) -> deque[ts]
        self.lateral = {}          # user -> set(hosts)
        self.cloud_fails = {}      # ip -> deque[ts]
        self.corr = {}             # ip -> {category: (last ts, file)}
        self.last_seen = {}        # ip/key -> last event ts (for eviction)
        self.cooldown = {}         # emit key -> wallclock of last emission
        self.suppressed = defaultdict(int)  # emit key -> hits during cooldown
        self.malformed = defaultdict(int)   # file -> count
        self._last_evict = time.time()

    def touch(self, key, ts):
        self.last_seen[key] = ts

    def evict(self, now_ts):
        """Time-based eviction + hard size caps. Called periodically."""
        cutoff = now_ts - timedelta(seconds=STREAM_TTL_SEC)
        stale = [k for k, t in self.last_seen.items() if t and t < cutoff]
        for k in stale:
            self.last_seen.pop(k, None)
            for table in (self.ssh_fails, self.web_fails, self.ssh_users,
                          self.invalid_users, self.ports, self.rate,
                          self.notfound, self.scanpaths, self.lateral,
                          self.cloud_fails, self.corr):
                table.pop(k, None)
        for table in (self.ssh_fails, self.web_fails, self.rate, self.notfound,
                      self.ports, self.scanpaths, self.corr):
            while len(table) > STREAM_MAX_KEYS:
                table.pop(next(iter(table)))
        while len(self.beacons) > BEACON_MAX_KEYS:
            self.beacons.pop(next(iter(self.beacons)))
        # cooldown table: drop entries older than 2x any sane cooldown
        wall = time.time()
        for k in [k for k, t in self.cooldown.items() if wall - t > 7200]:
            self.cooldown.pop(k, None)


class Emitter:
    """Writes incidents as JSON-lines with per-key cooldown deduplication."""
    def __init__(self, out_path, cooldown_sec, quiet=False, metrics=None):
        self.out = open(out_path, "a") if out_path else None
        self.cooldown_sec = cooldown_sec
        self.quiet = quiet
        self.metrics = metrics
        self.emitted = 0
        self.suppressed_total = 0

    def emit(self, st, key, category, severity, title, description,
             entities, ev, mitre=""):
        wall = time.time()
        last = st.cooldown.get(key)
        if last is not None and wall - last < self.cooldown_sec:
            st.suppressed[key] += 1
            self.suppressed_total += 1
            if self.metrics:
                self.metrics.inc_suppressed()
            return False
        occurrences = st.suppressed.pop(key, 0) + 1
        st.cooldown[key] = wall
        rec = {
            "emitted_at": datetime.now(timezone.utc).isoformat(),
            "event_time": ev.ts.isoformat() if ev and ev.ts else None,
            "severity": severity, "category": category,
            "title": title, "description": description,
            "entities": entities, "mitre": mitre,
            "evidence": [f"{ev.file}:{ev.lineno}"] if ev else [],
            "occurrences_since_last_alert": occurrences,
        }
        line = json.dumps(rec)
        if self.out:
            self.out.write(line + "\n")
            self.out.flush()
        if not self.out or not self.quiet:
            print(line, flush=True)
        self.emitted += 1
        if self.metrics:
            self.metrics.inc_incident(severity, category)
        return True

    def close(self):
        if self.out:
            self.out.close()


def _win_ok(dq, count, window_sec):
    """True if the deque holds >= count timestamps spanning <= window_sec."""
    if len(dq) < count:
        return False
    return (dq[-1] - dq[-count]).total_seconds() <= window_sec


def _corr(st, em, ip, category, ev):
    """Live cross-source correlation: same IP across categories or files."""
    if not ip:
        return
    ts = ev.ts or datetime.now()
    entry = st.corr.setdefault(ip, {})
    entry[category] = (ts, ev.file)
    st.touch(ip, ts)
    cats = list(entry.keys())
    files = {f for _, f in entry.values()}
    if len(cats) >= 2 and len(files) >= 2:
        em.emit(st, ("corr", ip), "Cross-File Correlation", "critical",
                f"Multi-stage attack from {ip}: {' + '.join(sorted(cats))}",
                f"IP {ip} triggered {len(cats)} attack categories across "
                f"{len(files)} sources ({', '.join(sorted(files))}).",
                {"ips": [ip]}, ev, mitre="multiple")
    elif len(cats) == 1 and len(files) >= 2:
        em.emit(st, ("corr-svc", ip), "Cross-File Correlation", "critical",
                f"Coordinated multi-service attack from {ip} "
                f"({cats[0]} against {len(files)} services)",
                f"The same category of attack from {ip} was seen in "
                f"{', '.join(sorted(files))}.", {"ips": [ip]}, ev,
                mitre="multiple")


def compile_stream_rules(cfg):
    rules = []
    for r in cfg["pattern_rules"]:
        try:
            rules.append((r, re.compile(r["regex"])))
        except re.error as exc:
            print(f"[!] Skipping invalid rule {r.get('id')}: {exc}",
                  file=sys.stderr)
    return rules


def process_event(ev, st, cfg, em, rules):
    """Run every streaming detector against one event, then discard it."""
    th = cfg["thresholds"]
    ts = ev.ts or datetime.now()
    ip = ev.src_ip

    if ev.kind == "malformed":
        st.malformed[ev.file] += 1
        if st.malformed[ev.file] == 1:
            em.emit(st, ("malformed", ev.file), "Data Quality", "info",
                    f"Malformed/unparseable line(s) in {ev.file}",
                    "Lines matching no known format. Could indicate tampering, "
                    "corruption, or an unsupported format. Further occurrences "
                    "are counted, not re-alerted.",
                    {}, ev)
        return

    # ---- pattern rules (all 17 config-driven categories) ----
    for rule, rx in rules:
        val = getattr(ev, rule.get("field", "message"), None) or ""
        if rx.search(val):
            entity = ip or ev.user or ev.file
            fired = em.emit(st, (rule["id"], entity), rule["category"],
                            rule["severity"],
                            f'{rule["description"]} ({entity})',
                            f'Rule {rule["id"]} matched on '
                            f'"{rule.get("field", "message")}".',
                            {"ips": [ip] if ip else [],
                             "users": [ev.user] if ev.user else []},
                            ev, mitre=rule.get("mitre", ""))
            if fired:
                _corr(st, em, ip, rule["category"], ev)

    # ---- SSH auth ----
    if ev.kind == "syslog":
        msg = ev.message or ""
        if ip and FAILED_SSH.search(msg):
            st.touch(ip, ts)
            dq = st.ssh_fails.setdefault(ip, deque(maxlen=200))
            dq.append(ts)
            if ev.user:
                st.ssh_users.setdefault(ip, set()).add(ev.user)
                if len(st.ssh_users[ip]) >= th["password_spray"]["users"]:
                    if em.emit(st, ("spray", ip), "Credential Attacks", "high",
                               f"Password spraying from {ip} across "
                               f"{len(st.ssh_users[ip])} accounts",
                               "One source attempting many distinct usernames.",
                               {"ips": [ip]}, ev, mitre="T1110.003"):
                        _corr(st, em, ip, "Credential Attacks", ev)
            m = INVALID_USER_RE.search(msg)
            if m:
                st.invalid_users.setdefault(ip, set()).add(m.group(1))
                if len(st.invalid_users[ip]) >= th["invalid_user_enum"]["count"]:
                    if em.emit(st, ("enum", ip), "Reconnaissance", "medium",
                               f"SSH username enumeration from {ip}",
                               f"Attempts on invalid users: "
                               f"{', '.join(sorted(st.invalid_users[ip])[:8])}.",
                               {"ips": [ip]}, ev, mitre="T1589.001"):
                        _corr(st, em, ip, "Reconnaissance", ev)
            if _win_ok(dq, th["brute_force"]["count"],
                       th["brute_force"]["window_sec"]):
                if em.emit(st, ("ssh-brute", ip), "Brute Force Attacks", "high",
                           f"SSH brute force from {ip} "
                           f"({len(dq)} recent failures)",
                           "Failed-authentication volume exceeded threshold.",
                           {"ips": [ip]}, ev, mitre="T1110"):
                    _corr(st, em, ip, "Brute Force Attacks", ev)

        am = ACCEPTED_SSH.search(msg)
        if am and ip:
            fails = st.ssh_fails.get(ip)
            if fails and len(fails) >= th["web_login_success_min_fails"]:
                em.emit(st, ("ssh-compromise", ip),
                        "Brute Force Attacks", "critical",
                        f"SSH brute force from {ip} SUCCEEDED "
                        f"(login as '{am.group(2)}' after {len(fails)} failures)",
                        "Accepted login followed failures from the same IP — "
                        "treat the account as compromised.",
                        {"ips": [ip], "users": [am.group(2)]}, ev,
                        mitre="T1110/T1078")
                _corr(st, em, ip, "Unauthorized Access", ev)
                fails.clear()
            # lateral movement
            if is_internal(ip, cfg) and ev.host:
                hosts = st.lateral.setdefault(am.group(2), set())
                hosts.add(ev.host)
                st.touch(am.group(2), ts)
                if len(hosts) >= 3:
                    em.emit(st, ("lateral", am.group(2)),
                            "Lateral Movement", "high",
                            f"Account '{am.group(2)}' hopped across "
                            f"{len(hosts)} internal hosts",
                            f"Internal SSH logins to: {', '.join(sorted(hosts))}.",
                            {"users": [am.group(2)], "ips": [ip]}, ev,
                            mitre="T1021.004")
            # insider off-hours
            oh = th["off_hours"]
            if is_internal(ip, cfg) and ev.ts and oh["start"] <= ev.ts.hour < oh["end"]:
                em.emit(st, ("insider", ev.user or ip),
                        "Insider Threats", "low",
                        f"Off-hours internal login by "
                        f"'{am.group(2)}' at {ev.ts.strftime('%H:%M')}",
                        "Successful internal login outside business hours.",
                        {"users": [am.group(2)], "ips": [ip]}, ev,
                        mitre="T1078")

        if "DPT=" in msg and ip:
            pm = PORT_RE.search(msg)
            if pm:
                st.ports.setdefault(ip, set()).add(pm.group(1))
                st.touch(ip, ts)
                if len(st.ports[ip]) >= th["port_scan"]["distinct_ports"]:
                    if em.emit(st, ("portscan", ip), "Network Attacks", "medium",
                               f"Port scan from {ip} "
                               f"({len(st.ports[ip])} distinct ports)",
                               "Firewall logged probes across many ports.",
                               {"ips": [ip]}, ev, mitre="T1046"):
                        _corr(st, em, ip, "Network Attacks", ev)

        if ev.process and ev.process.startswith("sudo"):
            um = SUDO_USER_RE.match(msg)
            user = um.group(1) if um else ev.user
            if re.search(r"(?i)(NOT in sudoers|incorrect password attempts|"
                         r"command not allowed|3 incorrect)", msg):
                em.emit(st, ("sudo-fail", user or "unknown"),
                        "Policy Violations", "medium",
                        f"Sudo misuse by '{user}'",
                        "Unauthorized privilege-escalation attempt.",
                        {"users": [user] if user else []}, ev,
                        mitre="T1548.003")
            else:
                cm = SUDO_CMD_RE.search(msg)
                if cm and SENSITIVE_SUDO_RE.search(cm.group(1)):
                    em.emit(st, ("sudo-sensitive", user or "unknown"),
                            "Credential Attacks", "high",
                            f"Sensitive sudo command by '{user}': "
                            f"{cm.group(1)[:80]}",
                            "Successful sudo touching credentials or "
                            "privilege configuration.",
                            {"users": [user] if user else []}, ev,
                            mitre="T1003.008")

    # ---- Web ----
    if ev.kind == "web" and ip:
        st.touch(ip, ts)
        rdq = st.rate.setdefault(ip, deque(maxlen=max(200, th["rate_limit"]["requests"])))
        rdq.append(ts)
        if _win_ok(rdq, th["rate_limit"]["requests"], th["rate_limit"]["window_sec"]):
            if em.emit(st, ("rate", ip), "Network Attacks", "medium",
                       f"Rate-limit abuse from {ip} "
                       f"(≥{th['rate_limit']['requests']} req/"
                       f"{th['rate_limit']['window_sec']}s)",
                       "Sustained request rate far above normal.",
                       {"ips": [ip]}, ev, mitre="T1498"):
                _corr(st, em, ip, "Network Attacks", ev)
        if ev.status == 429:
            em.emit(st, ("429", ip), "Rate-Limit Abuse", "medium",
                    f"Server throttled {ip} with HTTP 429 on {ev.path}",
                    "The application's own rate limiter fired.",
                    {"ips": [ip]}, ev, mitre="T1498")

        if ev.path and LOGIN_PATH.search(ev.path):
            if ev.status in (401, 403) and ev.method == "POST":
                dq = st.web_fails.setdefault(ip, deque(maxlen=200))
                dq.append(ts)
                if _win_ok(dq, th["web_login_brute"]["count"],
                           th["web_login_brute"]["window_sec"]):
                    if em.emit(st, ("web-brute", ip),
                               "Brute Force Attacks", "high",
                               f"Web login brute force from {ip}",
                               f"{len(dq)} recent failed login POSTs.",
                               {"ips": [ip]}, ev, mitre="T1110.001"):
                        _corr(st, em, ip, "Brute Force Attacks", ev)
            elif ev.status == 200:
                fails = st.web_fails.get(ip)
                if fails and len(fails) >= th["web_login_success_min_fails"]:
                    em.emit(st, ("web-compromise", ip),
                            "Brute Force Attacks", "critical",
                            f"Web login brute force from {ip} SUCCEEDED "
                            f"after {len(fails)} failures",
                            "HTTP 200 on a login endpoint after failed bursts — "
                            "probable account takeover.",
                            {"ips": [ip]}, ev, mitre="T1110.001/T1078")
                    _corr(st, em, ip, "Unauthorized Access", ev)
                    fails.clear()

        if ev.status == 404 and ev.path:
            dq = st.notfound.setdefault(ip, deque(maxlen=100))
            dq.append((ts, ev.path))
            recent = [p for t, p in dq
                      if (ts - t).total_seconds() <= th["recon_404"]["window_sec"]]
            if len(recent) >= th["recon_404"]["count"] and \
               len(set(recent)) >= th["recon_404"]["count"] // 2:
                if em.emit(st, ("404", ip), "Reconnaissance", "medium",
                           f"Forced-browsing / enumeration from {ip}",
                           f"{len(recent)} 404s across "
                           f"{len(set(recent))} paths.",
                           {"ips": [ip]}, ev, mitre="T1595.003"):
                    _corr(st, em, ip, "Reconnaissance", ev)

        if ev.path and ev.status in (400, 401, 403, 404) and \
           SCAN_PATH_RE.search(ev.path):
            paths = st.scanpaths.setdefault(ip, set())
            paths.add(ev.path)
            if len(paths) >= 4:
                if em.emit(st, ("vulnscan", ip), "Reconnaissance", "high",
                           f"Vulnerability scan from {ip} "
                           f"({len(paths)} sensitive endpoints)",
                           f"Probed: {', '.join(sorted(paths)[:8])}.",
                           {"ips": [ip]}, ev, mitre="T1595.003"):
                    _corr(st, em, ip, "Reconnaissance", ev)

        if (ev.size or 0) >= th["exfil_bytes"]:
            em.emit(st, ("exfil", ip), "Data Breaches", "critical",
                    f"Possible exfiltration to {ip} "
                    f"({ev.size/1e6:.0f} MB response: {ev.path})",
                    "Unusually large transfer.", {"ips": [ip]}, ev,
                    mitre="T1041")
            _corr(st, em, ip, "Data Breaches", ev)

        if ev.status == 200 and ev.path:
            key = (ip, ev.path)
            bd = st.beacons.setdefault(key, deque(maxlen=12))
            bd.append(ts)
            if len(bd) >= th["beacon_min_requests"]:
                gaps = [(b - a).total_seconds() for a, b in zip(bd, list(bd)[1:])]
                if gaps and min(gaps) >= 5:
                    mean = statistics.mean(gaps)
                    stdev = statistics.pstdev(gaps)
                    if mean >= 10 and stdev / mean <= th["beacon_max_jitter"]:
                        if em.emit(st, ("beacon", key),
                                   "Command and Control (C2)", "critical",
                                   f"Beaconing: {ip} → {ev.path} "
                                   f"every ~{mean:.0f}s",
                                   f"Regular interval, jitter "
                                   f"{stdev/mean:.1%}.",
                                   {"ips": [ip]}, ev, mitre="T1071.001"):
                            _corr(st, em, ip, "Command and Control (C2)", ev)

    # ---- Cloud (JSON) ----
    if ev.kind == "json" and CLOUD_FAIL.search(ev.message):
        dq = st.cloud_fails.setdefault(ip or "unknown", deque(maxlen=50))
        dq.append(ts)
        if len(dq) >= cfg["thresholds"]["cloud_login_failures"]["count"]:
            if em.emit(st, ("cloud-brute", ip), "Cloud Security Incidents",
                       "high",
                       f"Cloud console brute force from {ip}",
                       f"{len(dq)} failed ConsoleLogin events.",
                       {"ips": [ip] if ip else []}, ev, mitre="T1110"):
                _corr(st, em, ip, "Cloud Security Incidents", ev)

    # periodic eviction
    if time.time() - st._last_evict > 60:
        st.evict(ts)
        st._last_evict = time.time()


# --------------------------------------------------------------------------
# File following: rotation-aware, checkpointed
# --------------------------------------------------------------------------

class Follower:
    def __init__(self, paths, checkpoint_path, once=False):
        self.paths = paths
        self.ckpt = checkpoint_path
        self.once = once
        self.state = {}   # path -> {"inode": int, "offset": int, "lineno": int}
        if checkpoint_path and os.path.exists(checkpoint_path):
            try:
                with open(checkpoint_path) as f:
                    self.state = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"[!] Ignoring bad checkpoint: {e}", file=sys.stderr)

    def save(self):
        if not self.ckpt:
            return
        tmp = self.ckpt + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self.state, f)
            os.replace(tmp, self.ckpt)
        except OSError as e:
            print(f"[!] Checkpoint save failed: {e}", file=sys.stderr)

    def poll(self):
        """Yield (path, lineno, line) for every unseen line, handling
        rotation (inode change) and truncation (size < offset)."""
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
                s = {"inode": stt.st_ino, "offset": 0, "lineno": 0}
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
                        if not line.endswith("\n"):
                            # Incomplete trailing line: rewind so we re-read it
                            # once fully written. In --once mode there's no more
                            # writing, so process it as-is.
                            if not self.once:
                                f.seek(pos)
                                break
                        s["lineno"] += 1
                        yield path, s["lineno"], line
                        s["offset"] = f.tell()
            except OSError as e:
                print(f"[!] Read error on {path}: {e}", file=sys.stderr)


def _shard_owns(ev, shard_index, shard_total):
    """Deterministically assign an event to a shard by source IP (fallback:
    user, then file). Same key always lands on the same shard, so all state
    for a given attacker stays within one process.

    Uses a stable hash (md5) rather than Python's built-in hash(), which is
    randomized per-process via PYTHONHASHSEED and would send the same IP to
    different shards in different processes."""
    import hashlib
    key = (ev.src_ip or ev.user or ev.file or "").encode()
    digest = hashlib.md5(key).digest()
    return (int.from_bytes(digest[:4], "big") % shard_total) == shard_index


def stream_mode(args, cfg):
    # Checkpoint is per-shard so shards never clobber each other's offsets.
    ckpt = args.checkpoint
    if ckpt and args.shard_total > 1:
        ckpt = f"{ckpt}.shard{args.shard_index}"
    follower = Follower(args.files, ckpt, once=args.once)
    st = StreamState()
    metrics = Metrics() if args.metrics_port else None
    if metrics:
        metrics.files = len(args.files)
        if args.shard_total > 1:
            metrics.shard = (args.shard_index, args.shard_total)
        start_metrics_server(metrics, args.metrics_port)
    em = Emitter(args.output, args.cooldown, quiet=args.quiet, metrics=metrics)
    rules = compile_stream_rules(cfg)
    year = args.year
    lines_total = 0
    sharded = args.shard_total > 1
    stop = {"flag": False}

    def _sig(_s, _f):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    shard_note = (f"; shard {args.shard_index}/{args.shard_total}"
                  if sharded else "")
    print(f"[*] LogSentinel streaming: following {len(args.files)} file(s); "
          f"cooldown {args.cooldown}s; checkpoint "
          f"{ckpt or 'disabled'}{shard_note}", file=sys.stderr)

    last_ckpt = time.time()
    try:
        while not stop["flag"]:
            n = 0
            for path, lineno, line in follower.poll():
                ev = parse_line(line, os.path.basename(path), lineno, year)
                n += 1
                lines_total += 1
                # In sharded mode, skip events this shard doesn't own. We still
                # advanced the offset (every shard reads every line), so each
                # shard only *processes* its slice.
                if ev is not None and (not sharded or
                                       _shard_owns(ev, args.shard_index,
                                                   args.shard_total)):
                    process_event(ev, st, cfg, em, rules)
                    if metrics:
                        metrics.inc_line(ev.kind != "malformed")
                        if ev.kind == "malformed":
                            metrics.inc_malformed()
                        metrics.set_event_ts(ev.ts)
                if stop["flag"]:
                    break
            if time.time() - last_ckpt > 30:
                follower.save()
                last_ckpt = time.time()
            if n == 0:
                if args.once:
                    break
                time.sleep(args.poll_interval)
    finally:
        follower.save()
        em.close()
        print(f"[*] Processed {lines_total:,} lines"
              f"{shard_note} | {em.emitted} incidents emitted | "
              f"{em.suppressed_total} duplicate alerts suppressed by cooldown",
              file=sys.stderr)
    return 0

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="logsentinel",
        description="Analyze log files for potential security incidents.")
    ap.add_argument("files", nargs="+", help="log file(s) to analyze")
    ap.add_argument("--follow", action="store_true",
                    help="continuous streaming mode: tail files, emit JSONL "
                         "incidents live, bounded memory")
    ap.add_argument("--once", action="store_true",
                    help="with --follow: process available data then exit "
                         "(for testing / cron)")
    ap.add_argument("--output", metavar="PATH",
                    help="with --follow: append JSONL incidents to file")
    ap.add_argument("--quiet", action="store_true",
                    help="with --follow --output: don't echo incidents to stdout")
    ap.add_argument("--checkpoint", metavar="PATH",
                    default=".logsentinel.ckpt",
                    help="with --follow: file-position checkpoint "
                         "(default .logsentinel.ckpt; empty string disables)")
    ap.add_argument("--cooldown", type=int, default=300,
                    help="with --follow: seconds to suppress duplicate alerts "
                         "per detector+entity (default 300)")
    ap.add_argument("--poll-interval", type=float, default=1.0,
                    help="with --follow: seconds between polls when idle")
    ap.add_argument("--metrics-port", type=int, default=0,
                    help="with --follow: serve /health and /metrics on this "
                         "HTTP port (0 = disabled)")
    ap.add_argument("--shard-index", type=int, default=0,
                    help="with --follow: this shard's index (0-based)")
    ap.add_argument("--shard-total", type=int, default=1,
                    help="with --follow: total number of shards; events are "
                         "assigned to shards by source IP so each attacker's "
                         "state stays in one process")
    ap.add_argument("--rules", help="YAML rules/config file (extends defaults)")
    ap.add_argument("--json", metavar="PATH", help="write full JSON report")
    ap.add_argument("--csv", metavar="PATH", help="write CSV summary")
    ap.add_argument("--min-severity", default="info",
                    choices=list(SEV_ORDER), help="filter console output")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year for syslog timestamps (they omit it)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    cfg = load_config(args.rules)
    if args.follow:
        if args.shard_total < 1 or not (0 <= args.shard_index < args.shard_total):
            sys.exit(f"Invalid sharding: index {args.shard_index} must be in "
                     f"[0, {args.shard_total}) and total >= 1")
        if not args.checkpoint:
            args.checkpoint = None
        return stream_mode(args, cfg)
    events, stats = [], {"files": 0, "lines": 0, "parsed": 0, "malformed": 0}
    for path in args.files:
        if not os.path.isfile(path):
            print(f"[!] Not a file, skipping: {path}", file=sys.stderr)
            continue
        stats["files"] += 1
        with io.open(path, "r", errors="replace") as f:
            for n, line in enumerate(f, 1):
                stats["lines"] += 1
                ev = parse_line(line, os.path.basename(path), n, args.year)
                if ev is None:
                    continue
                if ev.kind == "malformed":
                    stats["malformed"] += 1
                else:
                    stats["parsed"] += 1
                events.append(ev)
    if not events:
        sys.exit("No events parsed — check the input paths.")

    incidents = []
    if cfg["detectors"].get("sqli") or cfg["detectors"].get("path_traversal") \
       or cfg["detectors"].get("malware") or True:
        detect_pattern_rules(events, cfg, incidents)
    # Pattern-rule categories can be disabled via config too:
    disabled_cats = {k for k, v in cfg["detectors"].items() if not v}
    for name, fn in DETECTOR_MAP.items():
        if cfg["detectors"].get(name, True):
            fn(events, cfg, incidents)
    if cfg["detectors"].get("correlation", True):
        detect_correlation(events, cfg, incidents)
    observations = []
    if cfg["detectors"].get("observations", True):
        detect_observations(events, cfg, incidents, observations)

    minsev = SEV_ORDER[args.min_severity]
    visible = [i for i in incidents if SEV_ORDER[i.severity] <= minsev]
    use_color = (not args.no_color) and sys.stdout.isatty()
    print_report(visible, stats, use_color, observations)

    if args.json:
        write_json(incidents, stats, args.json, observations)
        print(f"JSON report → {args.json}")
    if args.csv:
        write_csv(incidents, args.csv, observations)
        print(f"CSV summary → {args.csv}")

    if any(i.severity == "critical" for i in incidents):
        return 2
    return 1 if any(i.severity != "info" for i in incidents) else 0

if __name__ == "__main__":
    sys.exit(main())
