#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║          NetSentinel — Passive Threat Intelligence        ║
║          Network anomaly detection & threat analysis      ║
╚═══════════════════════════════════════════════════════════╝

Monitors active connections, detects threats, and produces
structured threat intelligence reports — no packet capture
privileges required for the core analysis engine. Credits reserved to 0xNullVector on github
"""

import sys
import os
import json
import time
import socket
import struct
import hashlib
import ipaddress
import threading
import subprocess
import collections
import re
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

import psutil
import requests

# ─── Graceful rich import ────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.columns import Columns
    from rich import box
    from rich.rule import Rule
    from rich.align import Align
    from rich.style import Style
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("[ERROR] Please install rich: pip install rich")
    sys.exit(1)

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatEvent:
    timestamp: str
    threat_type: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    source_ip: str
    dest_ip: str
    port: int
    description: str
    evidence: dict = field(default_factory=dict)
    mitre_tactic: str = ""
    mitre_technique: str = ""

@dataclass
class ConnectionRecord:
    pid: int
    process: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    first_seen: float
    last_seen: float
    bytes_sent: int = 0
    bytes_recv: int = 0
    flags: list = field(default_factory=list)

@dataclass
class HostProfile:
    ip: str
    hostnames: list = field(default_factory=list)
    ports_seen: set = field(default_factory=set)
    connection_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    threat_score: int = 0
    geo_country: str = "Unknown"
    geo_city: str = "Unknown"
    is_tor: bool = False
    is_vpn: bool = False
    asn: str = ""
    tags: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
#  THREAT INTELLIGENCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatIntelEngine:
    """Core detection logic — all heuristic-based, no external deps."""

    # Known malicious / suspicious port ranges and services
    SUSPICIOUS_PORTS = {
        # RATs & backdoors
        1080: "SOCKS Proxy / Possible C2",
        4444: "Metasploit default listener",
        5555: "Android ADB / possible RAT",
        6666: "IRC / possible botnet C2",
        6667: "IRC botnet",
        6668: "IRC botnet",
        6669: "IRC botnet",
        31337: "Back Orifice (elite hacker port)",
        12345: "NetBus RAT",
        54321: "Reverse shell common port",
        # Cryptomining
        3333:  "Monero mining pool (stratum)",
        4545:  "Crypto mining pool",
        14444: "XMR mining pool",
        45560: "Mining pool",
        # Data exfiltration
        9001:  "Tor default ORPort",
        9030:  "Tor directory port",
        9050:  "Tor SOCKS proxy",
        9150:  "Tor Browser SOCKS",
    }

    KNOWN_GOOD_PROCESSES = {
        "chrome", "firefox", "safari", "edge", "brave",
        "python3", "python", "node", "code", "cursor",
        "slack", "zoom", "teams", "discord",
        "sshd", "systemd", "kernel_task",
    }

    # Ports that should NEVER initiate outbound connections from a workstation
    OUTBOUND_NEVER = {20, 25, 53, 80, 110, 143, 443, 587, 993, 995, 8080, 8443}

    CRYPTO_POOL_DOMAINS = [
        "pool.minexmr.com", "xmrpool.eu", "supportxmr.com",
        "hashvault.pro", "nanopool.org", "f2pool.com",
        "nicehash.com", "mining.pool",
    ]

    TOR_EXIT_SUBNETS: list = []  # populated lazily

    def __init__(self):
        self.connection_history: dict[str, ConnectionRecord] = {}
        self.host_profiles: dict[str, HostProfile] = {}
        self.threat_events: list[ThreatEvent] = []
        self.port_scan_tracker: dict[str, dict] = collections.defaultdict(
            lambda: {"ports": set(), "first_seen": time.time(), "last_seen": time.time()}
        )
        self.dns_query_tracker: dict[str, list] = collections.defaultdict(list)
        self.baseline_connections: set = set()
        self.baseline_built = False
        self._lock = threading.Lock()
        self.stats = {
            "scans": 0,
            "threats_found": 0,
            "connections_analyzed": 0,
            "hosts_profiled": 0,
        }

    # ── IP helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def is_loopback(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return True

    @staticmethod
    def is_multicast(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_multicast
        except ValueError:
            return True

    # ── Geo / ASN lookup (free ipapi.co — no key needed) ──────────────────────

    def enrich_ip(self, ip: str) -> dict:
        if self.is_private(ip) or self.is_loopback(ip):
            return {"country": "Private", "city": "N/A", "org": "Internal", "is_tor": False}
        profile = self.host_profiles.get(ip)
        if profile and profile.geo_country != "Unknown":
            return {
                "country": profile.geo_country,
                "city": profile.geo_city,
                "org": profile.asn,
                "is_tor": profile.is_tor,
            }
        try:
            r = requests.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=3,
                headers={"User-Agent": "NetSentinel/1.0"},
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "is_tor": False,
                }
        except Exception:
            pass
        return {"country": "Unknown", "city": "Unknown", "org": "Unknown", "is_tor": False}

    # ── Detection methods ──────────────────────────────────────────────────────

    def check_suspicious_port(self, conn: ConnectionRecord) -> Optional[ThreatEvent]:
        port = conn.remote_port
        if port in self.SUSPICIOUS_PORTS:
            desc = self.SUSPICIOUS_PORTS[port]
            return ThreatEvent(
                timestamp=datetime.now().isoformat(),
                threat_type="SUSPICIOUS_PORT",
                severity="HIGH",
                source_ip=conn.local_addr,
                dest_ip=conn.remote_addr,
                port=port,
                description=f"Process '{conn.process}' connected to suspicious port {port}: {desc}",
                evidence={"process": conn.process, "pid": conn.pid, "port": port},
                mitre_tactic="Command and Control",
                mitre_technique="T1571 – Non-Standard Port",
            )
        return None

    def check_port_scan_victim(self, connections: list) -> list[ThreatEvent]:
        """Detect if THIS host is being port-scanned (many inbound SYN-like conns from one source)."""
        events = []
        inbound: dict[str, set] = collections.defaultdict(set)
        for c in connections:
            if not self.is_private(c.remote_addr) and not self.is_loopback(c.remote_addr):
                inbound[c.remote_addr].add(c.local_port)
        for src_ip, ports in inbound.items():
            if len(ports) >= 5:
                events.append(ThreatEvent(
                    timestamp=datetime.now().isoformat(),
                    threat_type="PORT_SCAN_DETECTED",
                    severity="HIGH",
                    source_ip=src_ip,
                    dest_ip="localhost",
                    port=0,
                    description=f"Possible port scan from {src_ip} — {len(ports)} ports probed: {sorted(ports)[:10]}",
                    evidence={"source": src_ip, "ports_probed": sorted(ports)},
                    mitre_tactic="Reconnaissance",
                    mitre_technique="T1046 – Network Service Discovery",
                ))
        return events

    def check_lateral_movement(self, connections: list) -> list[ThreatEvent]:
        """Detect connections to many internal hosts on admin ports."""
        events = []
        admin_ports = {22, 23, 135, 139, 445, 3389, 5985, 5986}
        internal_targets: dict[str, set] = collections.defaultdict(set)
        for c in connections:
            if self.is_private(c.remote_addr) and not self.is_loopback(c.remote_addr):
                if c.remote_port in admin_ports:
                    internal_targets[c.process].add(c.remote_addr)
        for proc, hosts in internal_targets.items():
            if len(hosts) >= 3:
                events.append(ThreatEvent(
                    timestamp=datetime.now().isoformat(),
                    threat_type="LATERAL_MOVEMENT",
                    severity="CRITICAL",
                    source_ip="localhost",
                    dest_ip=", ".join(list(hosts)[:5]),
                    port=0,
                    description=f"Process '{proc}' connecting to {len(hosts)} internal hosts on admin ports — possible lateral movement",
                    evidence={"process": proc, "targets": list(hosts), "admin_ports": list(admin_ports)},
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021 – Remote Services",
                ))
        return events

    def check_data_exfil_volume(self, proc_io: dict) -> list[ThreatEvent]:
        """Flag processes sending unusually large volumes of data."""
        events = []
        THRESHOLD_MB = 50
        for proc_name, stats in proc_io.items():
            sent_mb = stats.get("bytes_sent", 0) / (1024 * 1024)
            if sent_mb > THRESHOLD_MB:
                events.append(ThreatEvent(
                    timestamp=datetime.now().isoformat(),
                    threat_type="HIGH_VOLUME_EXFIL",
                    severity="HIGH",
                    source_ip="localhost",
                    dest_ip="external",
                    port=0,
                    description=f"Process '{proc_name}' has sent {sent_mb:.1f} MB — possible data exfiltration",
                    evidence={"process": proc_name, "sent_mb": round(sent_mb, 2)},
                    mitre_tactic="Exfiltration",
                    mitre_technique="T1048 – Exfiltration Over Alternative Protocol",
                ))
        return events

    def check_dns_anomaly(self, connections: list) -> list[ThreatEvent]:
        """Detect non-standard DNS resolvers (potential DNS tunneling or hijack)."""
        events = []
        TRUSTED_DNS = {
            "8.8.8.8", "8.8.4.4",        # Google
            "1.1.1.1", "1.0.0.1",        # Cloudflare
            "9.9.9.9", "149.112.112.112", # Quad9
            "208.67.222.222",             # OpenDNS
        }
        for c in connections:
            if c.remote_port == 53:
                if not self.is_private(c.remote_addr) and c.remote_addr not in TRUSTED_DNS:
                    events.append(ThreatEvent(
                        timestamp=datetime.now().isoformat(),
                        threat_type="SUSPICIOUS_DNS",
                        severity="MEDIUM",
                        source_ip=c.local_addr,
                        dest_ip=c.remote_addr,
                        port=53,
                        description=f"DNS query to non-standard resolver {c.remote_addr} by '{c.process}' — possible DNS tunneling or hijack",
                        evidence={"resolver": c.remote_addr, "process": c.process},
                        mitre_tactic="Exfiltration",
                        mitre_technique="T1071.004 – DNS Exfiltration",
                    ))
        return events

    def check_beaconing(self, connections: list) -> list[ThreatEvent]:
        """Detect periodic beaconing to same external host (C2 pattern)."""
        events = []
        now = time.time()
        seen: dict[tuple, list] = collections.defaultdict(list)
        for c in connections:
            if not self.is_private(c.remote_addr) and not self.is_loopback(c.remote_addr):
                key = (c.process, c.remote_addr, c.remote_port)
                seen[key].append(now)

        for (proc, ip, port), times in seen.items():
            # If same process+endpoint appears 3+ times in our live snapshot
            if len(times) >= 3:
                events.append(ThreatEvent(
                    timestamp=datetime.now().isoformat(),
                    threat_type="POTENTIAL_BEACONING",
                    severity="MEDIUM",
                    source_ip="localhost",
                    dest_ip=ip,
                    port=port,
                    description=f"Process '{proc}' has {len(times)} persistent connections to {ip}:{port} — possible C2 beaconing",
                    evidence={"process": proc, "remote": f"{ip}:{port}", "count": len(times)},
                    mitre_tactic="Command and Control",
                    mitre_technique="T1071 – Application Layer Protocol",
                ))
        return events

    def check_tor_usage(self, connections: list) -> list[ThreatEvent]:
        """Detect connections to Tor ports."""
        events = []
        TOR_PORTS = {9001, 9030, 9050, 9051, 9150, 9151}
        for c in connections:
            if c.remote_port in TOR_PORTS:
                events.append(ThreatEvent(
                    timestamp=datetime.now().isoformat(),
                    threat_type="TOR_USAGE",
                    severity="HIGH",
                    source_ip=c.local_addr,
                    dest_ip=c.remote_addr,
                    port=c.remote_port,
                    description=f"Process '{c.process}' connecting to Tor network port {c.remote_port}",
                    evidence={"process": c.process, "tor_port": c.remote_port},
                    mitre_tactic="Command and Control",
                    mitre_technique="T1090.003 – Multi-hop Proxy (Tor)",
                ))
        return events

    def check_unusual_parent(self) -> list[ThreatEvent]:
        """Detect processes with suspicious parent-child relationships."""
        events = []
        SUSPICIOUS_CHILDREN = {
            "cmd.exe", "powershell.exe", "powershell", "bash", "sh", "nc", "ncat", "netcat",
        }
        SUSPICIOUS_PARENTS = {
            "word.exe", "excel.exe", "outlook.exe", "winword",
            "acrobat.exe", "acrord32.exe",
            "chrome.exe", "firefox.exe", "iexplore.exe",
        }
        try:
            for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline"]):
                try:
                    pname = (proc.info["name"] or "").lower()
                    if pname in SUSPICIOUS_CHILDREN:
                        parent = psutil.Process(proc.info["ppid"])
                        parent_name = (parent.name() or "").lower()
                        if parent_name in SUSPICIOUS_PARENTS:
                            events.append(ThreatEvent(
                                timestamp=datetime.now().isoformat(),
                                threat_type="SUSPICIOUS_PROCESS_SPAWN",
                                severity="CRITICAL",
                                source_ip="localhost",
                                dest_ip="localhost",
                                port=0,
                                description=f"'{parent_name}' spawned '{pname}' (PID {proc.pid}) — possible macro/exploit execution",
                                evidence={
                                    "child": pname,
                                    "parent": parent_name,
                                    "cmdline": " ".join(proc.info.get("cmdline") or [])[:200],
                                },
                                mitre_tactic="Execution",
                                mitre_technique="T1059 – Command and Scripting Interpreter",
                            ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        return events

    def deduplicate_events(self, events: list[ThreatEvent]) -> list[ThreatEvent]:
        """Remove duplicate events within a short window."""
        seen = set()
        unique = []
        for e in events:
            key = hashlib.md5(
                f"{e.threat_type}:{e.source_ip}:{e.dest_ip}:{e.port}".encode()
            ).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(e)
        return unique


# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkCollector:
    """Collects live network state via psutil (no raw packet capture needed)."""

    def __init__(self):
        self._proc_cache: dict[int, str] = {}

    def _get_proc_name(self, pid: int) -> str:
        if pid in self._proc_cache:
            return self._proc_cache[pid]
        try:
            name = psutil.Process(pid).name()
            self._proc_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"pid:{pid}"

    def get_connections(self) -> list[ConnectionRecord]:
        records = []
        now = time.time()
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            # On macOS without sudo, fallback to tcp
            try:
                conns = psutil.net_connections(kind="tcp")
            except Exception:
                return []

        for c in conns:
            if not c.raddr:
                continue
            try:
                rec = ConnectionRecord(
                    pid=c.pid or 0,
                    process=self._get_proc_name(c.pid or 0),
                    local_addr=c.laddr.ip if c.laddr else "",
                    local_port=c.laddr.port if c.laddr else 0,
                    remote_addr=c.raddr.ip,
                    remote_port=c.raddr.port,
                    status=c.status or "UNKNOWN",
                    first_seen=now,
                    last_seen=now,
                )
                records.append(rec)
            except Exception:
                continue
        return records

    def get_process_io_stats(self) -> dict:
        """Per-process network IO counters."""
        stats = {}
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    io = proc.io_counters()
                    name = proc.info["name"] or f"pid:{proc.pid}"
                    if name in stats:
                        stats[name]["bytes_sent"] += io.write_bytes
                        stats[name]["bytes_recv"] += io.read_bytes
                    else:
                        stats[name] = {
                            "bytes_sent": io.write_bytes,
                            "bytes_recv": io.read_bytes,
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    pass
        except Exception:
            pass
        return stats

    def get_listening_ports(self) -> list[dict]:
        """All locally listening ports."""
        ports = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.laddr:
                    ports.append({
                        "port": c.laddr.port,
                        "ip": c.laddr.ip,
                        "pid": c.pid,
                        "process": self._get_proc_name(c.pid or 0),
                    })
        except Exception:
            pass
        return ports

    def get_system_metrics(self) -> dict:
        net = psutil.net_io_counters()
        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "errin": net.errin,
            "errout": net.errout,
            "dropin": net.dropin,
            "dropout": net.dropout,
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
        }

    def get_arp_table(self) -> list[dict]:
        """Parse ARP table to detect spoofing (duplicate IPs for same MAC)."""
        entries = []
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                # Parse: hostname (IP) at MAC on iface
                m = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line, re.I
                )
                if m:
                    entries.append({"ip": m.group(1), "mac": m.group(2).lower()})
        except Exception:
            pass
        return entries

    def check_arp_spoofing(self, arp_table: list[dict]) -> list[ThreatEvent]:
        """Detect ARP spoofing: multiple IPs sharing same MAC, or gateway MAC change."""
        events = []
        mac_to_ips: dict[str, list] = collections.defaultdict(list)
        for entry in arp_table:
            mac_to_ips[entry["mac"]].append(entry["ip"])
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1 and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                events.append(ThreatEvent(
                    timestamp=datetime.now().isoformat(),
                    threat_type="ARP_SPOOFING",
                    severity="CRITICAL",
                    source_ip=ips[0],
                    dest_ip=ips[1],
                    port=0,
                    description=f"ARP spoofing detected: MAC {mac} claimed by multiple IPs: {ips}",
                    evidence={"mac": mac, "ips": ips},
                    mitre_tactic="Credential Access / Man-in-the-Middle",
                    mitre_technique="T1557.002 – ARP Cache Poisoning",
                ))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def generate_json_report(
        self,
        threats: list[ThreatEvent],
        connections: list[ConnectionRecord],
        metrics: dict,
        listening: list[dict],
        arp: list[dict],
        duration_seconds: float,
    ) -> dict:
        sorted_threats = sorted(threats, key=lambda x: self.SEVERITY_ORDER.get(x.severity, 99))
        threat_summary = collections.Counter(t.severity for t in sorted_threats)
        tactic_summary = collections.Counter(t.mitre_tactic for t in sorted_threats if t.mitre_tactic)

        return {
            "report_metadata": {
                "tool": "NetSentinel",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "hostname": socket.gethostname(),
                "analysis_duration_seconds": round(duration_seconds, 1),
            },
            "executive_summary": {
                "total_threats": len(sorted_threats),
                "by_severity": dict(threat_summary),
                "by_mitre_tactic": dict(tactic_summary),
                "active_connections": len(connections),
                "listening_ports": len(listening),
                "risk_level": self._overall_risk(threat_summary),
            },
            "threat_events": [asdict(t) for t in sorted_threats],
            "network_state": {
                "active_connections": [
                    {
                        "process": c.process,
                        "pid": c.pid,
                        "local": f"{c.local_addr}:{c.local_port}",
                        "remote": f"{c.remote_addr}:{c.remote_port}",
                        "status": c.status,
                    }
                    for c in connections[:50]
                ],
                "listening_ports": listening,
                "arp_table": arp,
            },
            "system_metrics": metrics,
            "recommendations": self._generate_recommendations(sorted_threats),
        }

    def _overall_risk(self, summary: dict) -> str:
        if summary.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        if summary.get("HIGH", 0) > 2:
            return "HIGH"
        if summary.get("HIGH", 0) > 0 or summary.get("MEDIUM", 0) > 3:
            return "MEDIUM"
        if summary.get("MEDIUM", 0) > 0:
            return "LOW"
        return "CLEAN"

    def _generate_recommendations(self, threats: list[ThreatEvent]) -> list[str]:
        recs = set()
        types = {t.threat_type for t in threats}
        if "ARP_SPOOFING" in types:
            recs.add("Enable dynamic ARP inspection (DAI) on managed switches.")
            recs.add("Use static ARP entries for critical hosts.")
        if "SUSPICIOUS_PORT" in types:
            recs.add("Investigate processes connecting to high-risk ports immediately.")
            recs.add("Review firewall egress rules to block unnecessary outbound traffic.")
        if "TOR_USAGE" in types:
            recs.add("Block Tor exit nodes and known Tor ports at the firewall level.")
        if "LATERAL_MOVEMENT" in types:
            recs.add("Implement network segmentation to limit lateral movement.")
            recs.add("Enable multi-factor authentication on all admin interfaces.")
        if "SUSPICIOUS_PROCESS_SPAWN" in types:
            recs.add("Investigate macro-enabled documents and disable Office macros.")
            recs.add("Deploy EDR solution with process lineage monitoring.")
        if "HIGH_VOLUME_EXFIL" in types:
            recs.add("Implement DLP (Data Loss Prevention) policies.")
            recs.add("Monitor outbound traffic volume per process.")
        if not recs:
            recs.add("Continue monitoring — no immediate threats detected.")
            recs.add("Ensure firewall egress rules are up to date.")
        return sorted(recs)


# ═══════════════════════════════════════════════════════════════════════════════
#  RICH DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

class Dashboard:

    SEVERITY_COLORS = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "bold yellow",
        "LOW": "bold cyan",
        "INFO": "dim white",
    }

    SEVERITY_ICONS = {
        "CRITICAL": "💀",
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪",
    }

    def __init__(self, engine: ThreatIntelEngine):
        self.engine = engine
        self.start_time = time.time()

    def _header(self) -> Panel:
        elapsed = int(time.time() - self.start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        title = Text()
        title.append("⚡ ", style="bold yellow")
        title.append("NET", style="bold white")
        title.append("SENTINEL", style="bold red")
        title.append("  ·  ", style="dim")
        title.append(f"Passive Threat Intelligence Engine", style="italic dim white")
        title.append("  ·  ", style="dim")
        title.append(f"⏱ {h:02d}:{m:02d}:{s:02d}", style="cyan")
        title.append(f"  ·  🖥 {socket.gethostname()}", style="dim")
        title.append(f"  ·  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim")
        return Panel(Align.center(title), style="bold blue", padding=(0, 1))

    def _stats_bar(self, threats: list, connections: list, metrics: dict) -> Table:
        t = Table.grid(expand=True)
        t.add_column(ratio=1)
        t.add_column(ratio=1)
        t.add_column(ratio=1)
        t.add_column(ratio=1)
        t.add_column(ratio=1)

        crit = sum(1 for x in threats if x.severity == "CRITICAL")
        high = sum(1 for x in threats if x.severity == "HIGH")
        med  = sum(1 for x in threats if x.severity == "MEDIUM")

        net_mb_in  = metrics.get("bytes_recv", 0) / (1024**2)
        net_mb_out = metrics.get("bytes_sent", 0) / (1024**2)

        def stat_panel(label, value, style, icon):
            return Panel(
                Align.center(Text(f"{icon}  {value}", style=style)),
                title=f"[dim]{label}[/dim]",
                border_style=style.replace("bold ", ""),
                padding=(0, 1),
            )

        t.add_row(
            stat_panel("CRITICAL", str(crit), "bold red", "💀"),
            stat_panel("HIGH", str(high), "bold orange1", "🔴"),
            stat_panel("MEDIUM", str(med), "bold yellow", "🟡"),
            stat_panel("CONNECTIONS", str(len(connections)), "bold cyan", "🔗"),
            stat_panel("NET IN/OUT", f"{net_mb_in:.1f}/{net_mb_out:.1f} MB", "bold green", "📡"),
        )
        return t

    def _threats_table(self, threats: list[ThreatEvent]) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold white on grey23",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Time", style="dim", width=10)
        table.add_column("Sev", width=10)
        table.add_column("Type", width=24)
        table.add_column("Source → Dest", width=30)
        table.add_column("Description")
        table.add_column("MITRE", width=12)

        if not threats:
            table.add_row(
                "", "", "[dim green]✓ No threats detected[/dim green]", "", "", ""
            )
        else:
            # show most recent / most severe
            shown = sorted(threats, key=lambda x: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.severity, 9)
            ))[:20]
            for t in shown:
                sev_style = self.SEVERITY_COLORS.get(t.severity, "white")
                icon = self.SEVERITY_ICONS.get(t.severity, "")
                ts = t.timestamp[11:19] if len(t.timestamp) > 19 else t.timestamp
                route = f"{t.source_ip[:15]} → {t.dest_ip[:15]}"
                mitre_id = t.mitre_technique.split("–")[0].strip() if t.mitre_technique else ""
                table.add_row(
                    ts,
                    Text(f"{icon} {t.severity}", style=sev_style),
                    Text(t.threat_type, style="bold"),
                    Text(route, style="dim cyan"),
                    Text(t.description[:70] + ("…" if len(t.description) > 70 else ""), style="white"),
                    Text(mitre_id, style="dim yellow"),
                )

        return Panel(table, title="[bold red] Threat Events[/bold red]", border_style="red")

    def _connections_table(self, connections: list[ConnectionRecord]) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold white on grey23",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Process", width=18)
        table.add_column("PID", width=7)
        table.add_column("Local", width=22)
        table.add_column("Remote", width=22)
        table.add_column("Status", width=14)

        # Sort: ESTABLISHED first, then by remote addr
        shown = sorted(connections, key=lambda c: (0 if c.status == "ESTABLISHED" else 1, c.remote_addr))[:15]
        for c in shown:
            status_style = "green" if c.status == "ESTABLISHED" else "dim"
            remote_style = "cyan" if not ThreatIntelEngine.is_private(c.remote_addr) else "dim white"
            table.add_row(
                Text(c.process[:18], style="bold"),
                str(c.pid),
                f"{c.local_addr}:{c.local_port}",
                Text(f"{c.remote_addr}:{c.remote_port}", style=remote_style),
                Text(c.status, style=status_style),
            )

        return Panel(table, title="[bold cyan]🔗 Active Connections[/bold cyan]", border_style="cyan")

    def _listening_panel(self, listening: list[dict]) -> Panel:
        table = Table(box=box.SIMPLE, show_header=True, expand=True, padding=(0, 1))
        table.add_column("Port", style="yellow bold", width=8)
        table.add_column("Process", width=16)
        table.add_column("Bind IP")

        RISKY = {21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5900}
        for p in listening[:12]:
            port_style = "bold red" if p["port"] in RISKY else "yellow"
            table.add_row(
                Text(str(p["port"]), style=port_style),
                p["process"][:16],
                p["ip"],
            )

        return Panel(table, title="[bold yellow]👂 Listening Ports[/bold yellow]", border_style="yellow")

    def _system_metrics_panel(self, metrics: dict) -> Panel:
        cpu = metrics.get("cpu_percent", 0)
        mem = metrics.get("memory_percent", 0)
        errs = metrics.get("errin", 0) + metrics.get("errout", 0)

        cpu_bar = self._bar(cpu, 100, width=20, color="red" if cpu > 80 else "green")
        mem_bar = self._bar(mem, 100, width=20, color="red" if mem > 85 else "green")

        content = Text()
        content.append("CPU   ", style="dim")
        content.append(cpu_bar)
        content.append(f"  {cpu:.0f}%\n", style="bold")
        content.append("MEM   ", style="dim")
        content.append(mem_bar)
        content.append(f"  {mem:.0f}%\n", style="bold")
        content.append(f"\nNet Errors:  ", style="dim")
        content.append(str(errs), style="bold red" if errs > 0 else "green")
        content.append(f"\nDropped Pkts: ", style="dim")
        content.append(str(metrics.get("dropin", 0) + metrics.get("dropout", 0)), style="bold")

        return Panel(content, title="[bold green]📊 System[/bold green]", border_style="green")

    @staticmethod
    def _bar(value: float, max_val: float, width: int = 20, color: str = "green") -> Text:
        filled = int((value / max_val) * width)
        bar = "█" * filled + "░" * (width - filled)
        return Text(bar, style=color)

    def render(
        self,
        threats: list[ThreatEvent],
        connections: list[ConnectionRecord],
        metrics: dict,
        listening: list[dict],
        scan_count: int,
    ) -> str:
        """Return a renderable layout."""
        layout = Layout()
        layout.split_column(
            Layout(self._header(), name="header", size=3),
            Layout(name="stats", size=5),
            Layout(name="main", ratio=1),
            Layout(name="bottom", size=16),
        )
        layout["stats"].update(self._stats_bar(threats, connections, metrics))
        layout["main"].split_row(
            Layout(self._threats_table(threats), name="threats", ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["right"].split_column(
            Layout(self._listening_panel(listening), name="listening"),
            Layout(self._system_metrics_panel(metrics), name="sysmetrics"),
        )
        layout["bottom"].update(self._connections_table(connections))
        return layout


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MONITOR LOOP
# ═══════════════════════════════════════════════════════════════════════════════

class NetSentinel:
    def __init__(self, duration: int = 60, report_path: str = "netsentinel_report.json"):
        self.duration = duration
        self.report_path = report_path
        self.engine = ThreatIntelEngine()
        self.collector = NetworkCollector()
        self.dashboard = Dashboard(self.engine)
        self.reporter = ReportGenerator()
        self.all_threats: list[ThreatEvent] = []
        self.seen_threat_keys: set = set()

    def _dedup_and_add(self, new_threats: list[ThreatEvent]):
        for t in new_threats:
            key = hashlib.md5(
                f"{t.threat_type}:{t.source_ip}:{t.dest_ip}:{t.port}".encode()
            ).hexdigest()
            if key not in self.seen_threat_keys:
                self.seen_threat_keys.add(key)
                self.all_threats.append(t)
                self.engine.stats["threats_found"] += 1

    def run(self):
        console.print(Panel.fit(
            "[bold red]NetSentinel[/bold red] [white]— Passive Network Threat Intelligence[/white]\n"
            f"[dim]Analyzing for [cyan]{self.duration}s[/cyan] · Report → [cyan]{self.report_path}[/cyan][/dim]\n"
            "[dim yellow]Press Ctrl+C to stop and save report early[/dim yellow]",
            border_style="bold blue",
        ))
        time.sleep(1)

        start = time.time()
        last_metrics = self.collector.get_system_metrics()
        scan_count = 0

        with Live(console=console, refresh_per_second=1, screen=True) as live:
            try:
                while time.time() - start < self.duration:
                    scan_count += 1
                    self.engine.stats["scans"] = scan_count

                    # Collect
                    connections = self.collector.get_connections()
                    metrics = self.collector.get_system_metrics()
                    listening = self.collector.get_listening_ports()
                    arp_table = self.collector.get_arp_table()
                    proc_io = self.collector.get_process_io_stats()

                    self.engine.stats["connections_analyzed"] = len(connections)

                    # Detect
                    new_threats = []
                    for c in connections:
                        t = self.engine.check_suspicious_port(c)
                        if t:
                            new_threats.append(t)

                    new_threats += self.engine.check_port_scan_victim(connections)
                    new_threats += self.engine.check_lateral_movement(connections)
                    new_threats += self.engine.check_dns_anomaly(connections)
                    new_threats += self.engine.check_tor_usage(connections)
                    new_threats += self.engine.check_beaconing(connections)
                    new_threats += self.engine.check_unusual_parent()
                    new_threats += self.collector.check_arp_spoofing(arp_table)
                    new_threats += self.engine.check_data_exfil_volume(proc_io)

                    self._dedup_and_add(new_threats)

                    # Render
                    layout = self.dashboard.render(
                        self.all_threats, connections, metrics, listening, scan_count
                    )
                    live.update(layout)

                    last_metrics = metrics
                    time.sleep(2)

            except KeyboardInterrupt:
                pass

        self._finalize(connections, last_metrics, listening, arp_table, time.time() - start)

    def _finalize(self, connections, metrics, listening, arp, duration):
        console.print("\n")
        console.rule("[bold red]Analysis Complete[/bold red]")

        report = self.reporter.generate_json_report(
            self.all_threats, connections, metrics, listening, arp, duration
        )

        Path(self.report_path).write_text(json.dumps(report, indent=2))

        # Print summary
        summary = report["executive_summary"]
        risk = summary["risk_level"]
        risk_style = {"CRITICAL": "bold red", "HIGH": "orange1", "MEDIUM": "yellow",
                      "LOW": "cyan", "CLEAN": "bold green"}.get(risk, "white")

        console.print(Panel(
            f"[bold]Risk Level:[/bold] [{risk_style}]{risk}[/{risk_style}]\n"
            f"[bold]Total Threats:[/bold] {summary['total_threats']}\n"
            f"[bold]Duration:[/bold] {duration:.0f}s\n"
            f"[bold]Report saved:[/bold] [cyan]{self.report_path}[/cyan]",
            title="[bold]📋 Executive Summary[/bold]",
            border_style="blue",
        ))

        if report["recommendations"]:
            console.print(Panel(
                "\n".join(f"• {r}" for r in report["recommendations"]),
                title="[bold yellow]💡 Recommendations[/bold yellow]",
                border_style="yellow",
            ))


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="NetSentinel — Passive Network Threat Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 netsentinel.py                    # 60-second scan
  python3 netsentinel.py -d 120             # 2-minute scan
  python3 netsentinel.py -d 300 -o report.json  # 5-min scan, custom output
        """,
    )
    parser.add_argument("-d", "--duration", type=int, default=60,
                        help="Analysis duration in seconds (default: 60)")
    parser.add_argument("-o", "--output", default="netsentinel_report.json",
                        help="Output JSON report path (default: netsentinel_report.json)")
    args = parser.parse_args()

    sentinel = NetSentinel(duration=args.duration, report_path=args.output)
    sentinel.run()


if __name__ == "__main__":
    main()
