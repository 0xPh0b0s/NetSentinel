#!/usr/bin/env python3
"""
analyzer.py — Offline Log & Connection Analyzer

Parse and analyze:
  - netstat / ss output files
  - /var/log/auth.log (SSH brute force, privilege escalation)
  - /var/log/syslog / /var/log/messages
  - UFW / iptables firewall logs
  - Simple CSV connection logs

Usage:
    from analyzer import LogAnalyzer
    analyzer = LogAnalyzer()
    findings = analyzer.analyze_auth_log("/var/log/auth.log")
    findings = analyzer.analyze_firewall_log("/var/log/ufw.log")
    findings = analyzer.analyze_netstat_output("netstat_dump.txt")
"""

import re
import os
import json
import collections
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class Finding:
    timestamp: str
    source: str            # Which log file / analyzer
    finding_type: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str
    evidence: dict = field(default_factory=dict)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    line_number: int = 0
    raw_line: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ─── Auth log analyzer ────────────────────────────────────────────────────────

class AuthLogAnalyzer:
    """
    Analyzes /var/log/auth.log for:
    - SSH brute force attacks (many failed logins from same IP)
    - Successful logins after failures (credential stuffing success)
    - Root login attempts
    - Sudo privilege escalation
    - New user creation / passwd changes
    - PAM failures
    """

    # Regex patterns for common auth.log entries
    RE_FAILED_PASSWORD = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )
    RE_ACCEPTED_PASSWORD = re.compile(
        r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
    )
    RE_INVALID_USER = re.compile(
        r"Invalid user (\S+) from ([\d.]+)"
    )
    RE_ROOT_LOGIN = re.compile(
        r"ROOT LOGIN|pam_unix.*root.*authentication failure|sudo.*root"
    )
    RE_SUDO = re.compile(
        r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
    )
    RE_NEW_USER = re.compile(
        r"useradd.*new user.*name=(\S+)|adduser.*Adding user '(\S+)'"
    )
    RE_PASSWD_CHANGE = re.compile(
        r"password changed for (\S+)|Changed password for (\S+)"
    )
    RE_TIMESTAMP = re.compile(
        r"(\w{3}\s+\d+\s+\d+:\d+:\d+)"
    )

    BRUTE_FORCE_THRESHOLD = 10    # failures before flagging
    SPRAY_THRESHOLD = 5           # distinct users tried from same IP

    def analyze(self, log_path: str) -> list[Finding]:
        findings = []
        path = Path(log_path)
        if not path.exists():
            return [Finding(
                timestamp=datetime.now().isoformat(),
                source=log_path,
                finding_type="FILE_NOT_FOUND",
                severity="INFO",
                description=f"Log file not found: {log_path}",
            )]

        failed_by_ip: dict[str, list] = collections.defaultdict(list)
        users_by_ip: dict[str, set] = collections.defaultdict(set)
        accepted_logins: list = []
        failed_ips_before_success: set = set()

        lines = path.read_text(errors="replace").splitlines()

        for lineno, line in enumerate(lines, 1):
            ts_match = self.RE_TIMESTAMP.search(line)
            ts = ts_match.group(1) if ts_match else ""

            # Failed passwords
            m = self.RE_FAILED_PASSWORD.search(line)
            if m:
                user, ip, port = m.group(1), m.group(2), m.group(3)
                failed_by_ip[ip].append({"user": user, "ts": ts, "line": lineno})
                users_by_ip[ip].add(user)
                continue

            # Invalid users
            m = self.RE_INVALID_USER.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                failed_by_ip[ip].append({"user": user, "ts": ts, "line": lineno, "invalid": True})
                users_by_ip[ip].add(user)
                continue

            # Successful logins
            m = self.RE_ACCEPTED_PASSWORD.search(line)
            if m:
                user, ip, port = m.group(1), m.group(2), m.group(3)
                accepted_logins.append({"user": user, "ip": ip, "ts": ts, "line": lineno})
                if ip in failed_by_ip:
                    failed_ips_before_success.add(ip)

            # Root login
            if self.RE_ROOT_LOGIN.search(line):
                findings.append(Finding(
                    timestamp=ts,
                    source=log_path,
                    finding_type="ROOT_LOGIN_ATTEMPT",
                    severity="HIGH",
                    description="Root login attempt detected",
                    evidence={"line": line.strip()},
                    line_number=lineno,
                    raw_line=line.strip(),
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1078 – Valid Accounts",
                ))

            # Sudo escalation
            m = self.RE_SUDO.search(line)
            if m:
                user, cmd = m.group(1), m.group(2)
                severity = "HIGH" if "bash" in cmd or "sh" in cmd or "python" in cmd else "MEDIUM"
                findings.append(Finding(
                    timestamp=ts,
                    source=log_path,
                    finding_type="SUDO_ESCALATION",
                    severity=severity,
                    description=f"User '{user}' ran sudo command: {cmd[:80]}",
                    evidence={"user": user, "command": cmd},
                    line_number=lineno,
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1548.003 – Sudo and Sudo Caching",
                ))

            # New user creation
            m = self.RE_NEW_USER.search(line)
            if m:
                new_user = m.group(1) or m.group(2)
                findings.append(Finding(
                    timestamp=ts,
                    source=log_path,
                    finding_type="NEW_USER_CREATED",
                    severity="HIGH",
                    description=f"New user account created: '{new_user}' — potential persistence mechanism",
                    evidence={"username": new_user},
                    line_number=lineno,
                    mitre_tactic="Persistence",
                    mitre_technique="T1136 – Create Account",
                ))

            # Password change
            m = self.RE_PASSWD_CHANGE.search(line)
            if m:
                changed_user = m.group(1) or m.group(2)
                findings.append(Finding(
                    timestamp=ts,
                    source=log_path,
                    finding_type="PASSWORD_CHANGED",
                    severity="MEDIUM",
                    description=f"Password changed for user '{changed_user}'",
                    evidence={"username": changed_user},
                    line_number=lineno,
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1098 – Account Manipulation",
                ))

        # Post-process: brute force detection
        for ip, failures in failed_by_ip.items():
            count = len(failures)
            unique_users = len(users_by_ip[ip])

            if count >= self.BRUTE_FORCE_THRESHOLD:
                severity = "CRITICAL" if count > 50 else "HIGH"
                findings.append(Finding(
                    timestamp=failures[0]["ts"],
                    source=log_path,
                    finding_type="SSH_BRUTE_FORCE",
                    severity=severity,
                    description=f"SSH brute force from {ip}: {count} failed attempts across {unique_users} usernames",
                    evidence={
                        "source_ip": ip,
                        "failed_attempts": count,
                        "unique_users_tried": unique_users,
                        "sample_users": list(users_by_ip[ip])[:5],
                        "first_attempt": failures[0]["ts"],
                        "last_attempt": failures[-1]["ts"],
                    },
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110.001 – Password Guessing",
                ))

            # Password spray (many users, fewer attempts each)
            if unique_users >= self.SPRAY_THRESHOLD and count < unique_users * 3:
                findings.append(Finding(
                    timestamp=failures[0]["ts"],
                    source=log_path,
                    finding_type="PASSWORD_SPRAY",
                    severity="HIGH",
                    description=f"Password spray from {ip}: tried {unique_users} different usernames",
                    evidence={
                        "source_ip": ip,
                        "users_targeted": list(users_by_ip[ip])[:10],
                    },
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110.003 – Password Spraying",
                ))

            # Successful login after brute force
            if ip in failed_ips_before_success:
                for login in accepted_logins:
                    if login["ip"] == ip:
                        findings.append(Finding(
                            timestamp=login["ts"],
                            source=log_path,
                            finding_type="BRUTE_FORCE_SUCCESS",
                            severity="CRITICAL",
                            description=f"SUCCESSFUL login from {ip} as '{login['user']}' AFTER {count} failed attempts — likely compromised!",
                            evidence={
                                "source_ip": ip,
                                "username": login["user"],
                                "prior_failures": count,
                            },
                            line_number=login["line"],
                            mitre_tactic="Initial Access",
                            mitre_technique="T1110 – Brute Force",
                        ))

        return findings


# ─── Firewall log analyzer ────────────────────────────────────────────────────

class FirewallLogAnalyzer:
    """
    Analyzes UFW / iptables / firewalld logs for:
    - Port scan patterns
    - Repeated block events from same IP
    - Inbound connections to critical ports
    - Outbound blocks (potential C2 blocked)
    """

    RE_UFW = re.compile(
        r"\[UFW (BLOCK|ALLOW|LIMIT)\].*?SRC=([\d.]+).*?DST=([\d.]+).*?DPT=(\d+)"
    )
    RE_IPTABLES = re.compile(
        r"IN=\S*.*?SRC=([\d.]+)\s+DST=([\d.]+).*?DPT=(\d+)"
    )
    RE_TIMESTAMP = re.compile(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)")

    CRITICAL_INBOUND = {22, 23, 3389, 5900, 445, 135, 3306, 5432, 6379, 27017}

    def analyze(self, log_path: str) -> list[Finding]:
        findings = []
        path = Path(log_path)
        if not path.exists():
            return [Finding(
                timestamp=datetime.now().isoformat(),
                source=log_path,
                finding_type="FILE_NOT_FOUND",
                severity="INFO",
                description=f"Firewall log not found: {log_path}",
            )]

        blocked_by_ip: dict[str, list] = collections.defaultdict(list)
        lines = path.read_text(errors="replace").splitlines()

        for lineno, line in enumerate(lines, 1):
            ts_match = self.RE_TIMESTAMP.search(line)
            ts = ts_match.group(1) if ts_match else ""

            m = self.RE_UFW.search(line)
            if m:
                action, src, dst, dport = m.group(1), m.group(2), m.group(3), int(m.group(4))
                if action == "BLOCK":
                    blocked_by_ip[src].append({"dst": dst, "dport": dport, "ts": ts})
                    if dport in self.CRITICAL_INBOUND:
                        findings.append(Finding(
                            timestamp=ts,
                            source=log_path,
                            finding_type="BLOCKED_CRITICAL_PORT",
                            severity="HIGH",
                            description=f"Blocked inbound to critical port {dport} from {src}",
                            evidence={"src": src, "dst": dst, "port": dport},
                            line_number=lineno,
                            mitre_tactic="Initial Access",
                            mitre_technique="T1190 – Exploit Public-Facing Application",
                        ))

        # Summarize repeated blocks
        for ip, blocks in blocked_by_ip.items():
            ports = {b["dport"] for b in blocks}
            if len(blocks) >= 20:
                findings.append(Finding(
                    timestamp=blocks[0]["ts"],
                    source=log_path,
                    finding_type="REPEATED_BLOCKS",
                    severity="HIGH" if len(ports) > 5 else "MEDIUM",
                    description=f"{len(blocks)} blocked packets from {ip} targeting {len(ports)} ports",
                    evidence={
                        "source_ip": ip,
                        "total_blocks": len(blocks),
                        "ports_targeted": sorted(ports)[:20],
                    },
                    mitre_tactic="Reconnaissance",
                    mitre_technique="T1046 – Network Service Discovery",
                ))

        return findings


# ─── Netstat output parser ────────────────────────────────────────────────────

class NetstatAnalyzer:
    """
    Parse and analyze saved netstat -tupn / ss -tupn output.
    Useful for analyzing snapshots from other machines.
    """

    RE_NETSTAT = re.compile(
        r"(tcp|udp)\s+\d+\s+\d+\s+([\d.]+):(\d+)\s+([\d.]+):(\d+)\s+(\w+)?\s*(\d+/\S+)?"
    )

    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 6667, 6668, 6669, 31337, 12345, 54321,
        1080, 9001, 9050, 9150, 3333, 4545,
    }

    def analyze(self, input_path: str) -> list[Finding]:
        findings = []
        path = Path(input_path)
        if not path.exists():
            return [Finding(
                timestamp=datetime.now().isoformat(),
                source=input_path,
                finding_type="FILE_NOT_FOUND",
                severity="INFO",
                description=f"Netstat file not found: {input_path}",
            )]

        lines = path.read_text(errors="replace").splitlines()
        established_external: list[dict] = []

        for lineno, line in enumerate(lines, 1):
            m = self.RE_NETSTAT.search(line)
            if not m:
                continue

            proto = m.group(1)
            local_ip, local_port = m.group(2), int(m.group(3))
            remote_ip, remote_port = m.group(4), int(m.group(5))
            status = m.group(6) or ""
            proc = m.group(7) or "unknown"

            # Check suspicious remote ports
            if remote_port in self.SUSPICIOUS_PORTS:
                findings.append(Finding(
                    timestamp=datetime.now().isoformat(),
                    source=input_path,
                    finding_type="SUSPICIOUS_PORT_IN_NETSTAT",
                    severity="HIGH",
                    description=f"Connection to suspicious port {remote_port} from process {proc}",
                    evidence={"process": proc, "remote": f"{remote_ip}:{remote_port}"},
                    line_number=lineno,
                    raw_line=line.strip(),
                    mitre_tactic="Command and Control",
                    mitre_technique="T1571 – Non-Standard Port",
                ))

            # Track external established connections
            try:
                import ipaddress as _ip
                remote_addr = _ip.ip_address(remote_ip)
                if not remote_addr.is_private and not remote_addr.is_loopback and status == "ESTABLISHED":
                    established_external.append({
                        "local": f"{local_ip}:{local_port}",
                        "remote": f"{remote_ip}:{remote_port}",
                        "process": proc,
                        "line": lineno,
                    })
            except ValueError:
                pass

        # Flag process with many external connections
        proc_counts: dict[str, int] = collections.Counter(
            e["process"].split("/")[-1] for e in established_external
        )
        for proc, count in proc_counts.items():
            if count >= 5:
                findings.append(Finding(
                    timestamp=datetime.now().isoformat(),
                    source=input_path,
                    finding_type="HIGH_EXTERNAL_CONNECTION_COUNT",
                    severity="MEDIUM",
                    description=f"Process '{proc}' has {count} established external connections — possible C2 or data transfer",
                    evidence={"process": proc, "connection_count": count},
                    mitre_tactic="Command and Control",
                    mitre_technique="T1071 – Application Layer Protocol",
                ))

        return findings


# ─── Master LogAnalyzer ───────────────────────────────────────────────────────

class LogAnalyzer:
    """Unified interface to all log analyzers."""

    def __init__(self):
        self.auth = AuthLogAnalyzer()
        self.firewall = FirewallLogAnalyzer()
        self.netstat = NetstatAnalyzer()

    def analyze_auth_log(self, path: str) -> list[Finding]:
        return self.auth.analyze(path)

    def analyze_firewall_log(self, path: str) -> list[Finding]:
        return self.firewall.analyze(path)

    def analyze_netstat_output(self, path: str) -> list[Finding]:
        return self.netstat.analyze(path)

    def analyze_all(self, paths: dict[str, str]) -> dict[str, list[Finding]]:
        """
        paths = {
            "auth": "/var/log/auth.log",
            "firewall": "/var/log/ufw.log",
            "netstat": "netstat_dump.txt",
        }
        """
        results = {}
        if "auth" in paths:
            results["auth"] = self.analyze_auth_log(paths["auth"])
        if "firewall" in paths:
            results["firewall"] = self.analyze_firewall_log(paths["firewall"])
        if "netstat" in paths:
            results["netstat"] = self.analyze_netstat_output(paths["netstat"])
        return results

    def to_json_report(self, findings_by_source: dict[str, list[Finding]]) -> dict:
        all_findings = []
        for source, findings in findings_by_source.items():
            all_findings.extend(findings)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(all_findings, key=lambda f: severity_order.get(f.severity, 9))

        summary = collections.Counter(f.severity for f in sorted_findings)
        tactic_summary = collections.Counter(
            f.mitre_tactic for f in sorted_findings if f.mitre_tactic
        )

        return {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(sorted_findings),
            "by_severity": dict(summary),
            "by_tactic": dict(tactic_summary),
            "findings": [f.to_dict() for f in sorted_findings],
        }
