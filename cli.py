#!/usr/bin/env python3
"""
cli.py — NetSentinel Unified Command-Line Interface

Subcommands:
  monitor     Live network threat monitoring (default)
  scan        One-shot connection + IOC scan
  analyze     Offline log file analysis
  ioc         Check specific IPs / domains / hashes
  report      Pretty-print a saved JSON report

Usage:
  python3 cli.py monitor -d 120
  python3 cli.py scan
  python3 cli.py analyze --auth /var/log/auth.log
  python3 cli.py analyze --firewall /var/log/ufw.log
  python3 cli.py ioc --ip 45.33.32.156
  python3 cli.py ioc --domain evil-payload-xyz.tk
  python3 cli.py ioc --hash e3b0c44298fc1c149afbf4c8996fb924...
  python3 cli.py report netsentinel_report.json
"""

import sys
import json
import argparse
import socket
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.rule import Rule

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim white",
}
SEVERITY_ICONS = {
    "CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪",
}


# ─── monitor ─────────────────────────────────────────────────────────────────

def cmd_monitor(args):
    from netsentinel import NetSentinel
    sentinel = NetSentinel(duration=args.duration, report_path=args.output)
    sentinel.run()


# ─── scan ─────────────────────────────────────────────────────────────────────

def cmd_scan(args):
    """One-shot: collect connections, run all detectors, IOC-check, print summary."""
    from netsentinel import NetworkCollector, ThreatIntelEngine, ReportGenerator
    from ioc_scanner import IOCScanner

    console.print(Panel.fit(
        "[bold red]NetSentinel[/bold red] [white]— One-Shot Scan[/white]\n"
        f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · {socket.gethostname()}[/dim]",
        border_style="blue",
    ))

    collector = NetworkCollector()
    engine = ThreatIntelEngine()
    ioc = IOCScanner(
        abuseipdb_key=args.abuseipdb_key or "",
        virustotal_key=args.vt_key or "",
    )

    with console.status("[bold cyan]Collecting network state…[/bold cyan]"):
        connections = collector.get_connections()
        metrics = collector.get_system_metrics()
        listening = collector.get_listening_ports()
        arp = collector.get_arp_table()
        proc_io = collector.get_process_io_stats()

    console.print(f"[green]✓[/green] Found [bold]{len(connections)}[/bold] connections, "
                  f"[bold]{len(listening)}[/bold] listening ports")

    with console.status("[bold cyan]Running threat detectors…[/bold cyan]"):
        threats = []
        for c in connections:
            t = engine.check_suspicious_port(c)
            if t:
                threats.append(t)
        threats += engine.check_port_scan_victim(connections)
        threats += engine.check_lateral_movement(connections)
        threats += engine.check_dns_anomaly(connections)
        threats += engine.check_tor_usage(connections)
        threats += engine.check_beaconing(connections)
        threats += engine.check_unusual_parent()
        threats += collector.check_arp_spoofing(arp)
        threats += engine.check_data_exfil_volume(proc_io)

    with console.status("[bold cyan]Checking IOCs…[/bold cyan]"):
        ioc_results = ioc.scan_connection_list(connections)
        malicious_ips = [r for r in ioc_results if r["is_malicious"]]

    # Print threats table
    console.print(Rule("[bold red]Threat Events[/bold red]"))
    if threats:
        table = Table(box=box.ROUNDED, expand=True)
        table.add_column("Severity", width=12)
        table.add_column("Type", width=26)
        table.add_column("Description")
        table.add_column("MITRE", width=14)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for t in sorted(threats, key=lambda x: sev_order.get(x.severity, 9)):
            sev_style = SEVERITY_COLORS.get(t.severity, "white")
            icon = SEVERITY_ICONS.get(t.severity, "")
            table.add_row(
                Text(f"{icon} {t.severity}", style=sev_style),
                Text(t.threat_type, style="bold"),
                t.description[:80],
                t.mitre_technique.split("–")[0].strip() if t.mitre_technique else "",
            )
        console.print(table)
    else:
        console.print("[green]✓ No threats detected[/green]")

    # Print malicious IPs
    if malicious_ips:
        console.print(Rule("[bold red]Malicious IPs Detected[/bold red]"))
        table = Table(box=box.ROUNDED)
        table.add_column("IP", style="red bold")
        table.add_column("Confidence")
        table.add_column("Tags")
        table.add_column("Description")
        for r in malicious_ips:
            table.add_row(
                r["ip"],
                f"{r['confidence']}%",
                ", ".join(r["tags"]),
                r["description"][:60],
            )
        console.print(table)

    # Save report
    reporter = ReportGenerator()
    report = reporter.generate_json_report(threats, connections, metrics, listening, arp, 0)
    report["ioc_results"] = ioc_results
    out = args.output or "netsentinel_scan.json"
    Path(out).write_text(json.dumps(report, indent=2))
    console.print(f"\n[dim]Report saved → [cyan]{out}[/cyan][/dim]")


# ─── analyze ─────────────────────────────────────────────────────────────────

def cmd_analyze(args):
    """Offline log file analysis."""
    from analyzer import LogAnalyzer

    console.print(Panel.fit(
        "[bold yellow]NetSentinel[/bold yellow] [white]— Offline Log Analyzer[/white]",
        border_style="yellow",
    ))

    analyzer = LogAnalyzer()
    paths = {}
    if args.auth:
        paths["auth"] = args.auth
    if args.firewall:
        paths["firewall"] = args.firewall
    if args.netstat:
        paths["netstat"] = args.netstat

    if not paths:
        console.print("[red]No log files specified. Use --auth, --firewall, or --netstat[/red]")
        sys.exit(1)

    all_findings = []
    for log_type, log_path in paths.items():
        with console.status(f"[cyan]Analyzing {log_type} log: {log_path}[/cyan]"):
            if log_type == "auth":
                findings = analyzer.analyze_auth_log(log_path)
            elif log_type == "firewall":
                findings = analyzer.analyze_firewall_log(log_path)
            elif log_type == "netstat":
                findings = analyzer.analyze_netstat_output(log_path)
            else:
                findings = []
        console.print(f"[green]✓[/green] {log_type}: [bold]{len(findings)}[/bold] findings")
        all_findings.extend(findings)

    # Print findings
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(all_findings, key=lambda f: sev_order.get(f.severity, 9))

    console.print(Rule("[bold yellow]Findings[/bold yellow]"))
    if sorted_findings:
        table = Table(box=box.ROUNDED, expand=True)
        table.add_column("Severity", width=12)
        table.add_column("Type", width=30)
        table.add_column("Description")
        table.add_column("Line", width=6)
        for f in sorted_findings:
            sev_style = SEVERITY_COLORS.get(f.severity, "white")
            icon = SEVERITY_ICONS.get(f.severity, "")
            table.add_row(
                Text(f"{icon} {f.severity}", style=sev_style),
                Text(f.finding_type, style="bold"),
                f.description[:80],
                str(f.line_number) if f.line_number else "",
            )
        console.print(table)
    else:
        console.print("[green]✓ No findings[/green]")

    # Save
    out = args.output or "netsentinel_analysis.json"
    report = analyzer.to_json_report({k: [] for k in paths})
    report["findings"] = [f.to_dict() for f in sorted_findings]
    Path(out).write_text(json.dumps(report, indent=2))
    console.print(f"\n[dim]Report saved → [cyan]{out}[/cyan][/dim]")


# ─── ioc ─────────────────────────────────────────────────────────────────────

def cmd_ioc(args):
    """Check specific IOCs."""
    from ioc_scanner import IOCScanner

    scanner = IOCScanner(
        abuseipdb_key=args.abuseipdb_key or "",
        virustotal_key=args.vt_key or "",
    )

    console.print(Panel.fit(
        "[bold cyan]NetSentinel[/bold cyan] [white]— IOC Checker[/white]",
        border_style="cyan",
    ))

    results = []
    if args.ip:
        for ip in args.ip:
            with console.status(f"[cyan]Checking IP: {ip}[/cyan]"):
                r = scanner.scan_ip(ip)
            results.append(r)

    if args.domain:
        for domain in args.domain:
            with console.status(f"[cyan]Checking domain: {domain}[/cyan]"):
                r = scanner.scan_domain(domain)
            results.append(r)

    if args.hash:
        for h in args.hash:
            with console.status(f"[cyan]Checking hash: {h[:16]}…[/cyan]"):
                r = scanner.scan_hash(h)
            results.append(r)

    if not results:
        console.print("[red]No IOCs specified. Use --ip, --domain, or --hash[/red]")
        sys.exit(1)

    table = Table(box=box.ROUNDED, expand=True)
    table.add_column("IOC", style="bold")
    table.add_column("Type", width=8)
    table.add_column("Status", width=16)
    table.add_column("Confidence", width=12)
    table.add_column("Tags")
    table.add_column("Sources")
    table.add_column("Description")

    for r in results:
        status = Text("🔴 MALICIOUS", style="bold red") if r.is_malicious else Text("✅ CLEAN", style="bold green")
        table.add_row(
            r.ioc[:40],
            r.ioc_type,
            status,
            f"{r.confidence}%" if r.confidence > 0 else "–",
            ", ".join(r.tags) or "–",
            ", ".join(r.sources) or "–",
            (r.description or "–")[:50],
        )

    console.print(table)


# ─── report ──────────────────────────────────────────────────────────────────

def cmd_report(args):
    """Pretty-print a saved JSON report."""
    path = Path(args.file)
    if not path.exists():
        console.print(f"[red]File not found: {args.file}[/red]")
        sys.exit(1)

    data = json.loads(path.read_text())
    meta = data.get("report_metadata", data)
    summary = data.get("executive_summary", {})
    threats = data.get("threat_events", data.get("findings", []))
    recs = data.get("recommendations", [])

    risk = summary.get("risk_level", "UNKNOWN")
    risk_style = {"CRITICAL": "bold red", "HIGH": "orange1", "MEDIUM": "yellow",
                  "LOW": "cyan", "CLEAN": "bold green"}.get(risk, "white")

    console.print(Panel(
        f"[bold]Host:[/bold] {meta.get('hostname', '?')}\n"
        f"[bold]Generated:[/bold] {meta.get('generated_at', '?')}\n"
        f"[bold]Risk Level:[/bold] [{risk_style}]{risk}[/{risk_style}]\n"
        f"[bold]Total Threats:[/bold] {summary.get('total_threats', len(threats))}\n"
        f"[bold]By Severity:[/bold] {summary.get('by_severity', {})}",
        title="[bold]📋 Report Summary[/bold]",
        border_style="blue",
    ))

    if threats:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_threats = sorted(threats, key=lambda t: sev_order.get(t.get("severity", "INFO"), 9))

        table = Table(box=box.ROUNDED, expand=True, title="Threat / Finding Events")
        table.add_column("Severity", width=12)
        table.add_column("Type", width=28)
        table.add_column("Description")
        table.add_column("MITRE", width=12)

        for t in sorted_threats[:50]:  # cap at 50
            sev = t.get("severity", "INFO")
            sev_style = SEVERITY_COLORS.get(sev, "white")
            icon = SEVERITY_ICONS.get(sev, "")
            mitre = t.get("mitre_technique", "")
            mitre_id = mitre.split("–")[0].strip() if mitre else ""
            table.add_row(
                Text(f"{icon} {sev}", style=sev_style),
                Text(t.get("threat_type") or t.get("finding_type", "?"), style="bold"),
                (t.get("description", ""))[:80],
                mitre_id,
            )
        console.print(table)

    if recs:
        console.print(Panel(
            "\n".join(f"• {r}" for r in recs),
            title="[bold yellow]💡 Recommendations[/bold yellow]",
            border_style="yellow",
        ))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="⚡ NetSentinel — Passive Network Threat Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  monitor   Live network threat monitoring dashboard
  scan      Quick one-shot scan with IOC checking
  analyze   Offline log file analysis (auth, firewall, netstat)
  ioc       Check IPs, domains, or file hashes
  report    Pretty-print a saved JSON report

Examples:
  python3 cli.py monitor -d 120
  python3 cli.py scan -o report.json
  python3 cli.py analyze --auth /var/log/auth.log --firewall /var/log/ufw.log
  python3 cli.py ioc --ip 1.2.3.4 8.8.8.8 --domain evil.tk
  python3 cli.py report netsentinel_report.json
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # monitor
    p_mon = sub.add_parser("monitor", help="Live network threat monitoring")
    p_mon.add_argument("-d", "--duration", type=int, default=60, help="Seconds to monitor (default: 60)")
    p_mon.add_argument("-o", "--output", default="netsentinel_report.json", help="Report output path")

    # scan
    p_scan = sub.add_parser("scan", help="One-shot scan with IOC checking")
    p_scan.add_argument("-o", "--output", default="netsentinel_scan.json")
    p_scan.add_argument("--abuseipdb-key", dest="abuseipdb_key", default="", help="AbuseIPDB API key (optional)")
    p_scan.add_argument("--vt-key", dest="vt_key", default="", help="VirusTotal API key (optional)")

    # analyze
    p_ana = sub.add_parser("analyze", help="Offline log file analysis")
    p_ana.add_argument("--auth", help="Path to auth.log")
    p_ana.add_argument("--firewall", help="Path to ufw.log or iptables log")
    p_ana.add_argument("--netstat", help="Path to saved netstat -tupn output")
    p_ana.add_argument("-o", "--output", default="netsentinel_analysis.json")

    # ioc
    p_ioc = sub.add_parser("ioc", help="Check IOCs (IPs, domains, hashes)")
    p_ioc.add_argument("--ip", nargs="+", help="IP addresses to check")
    p_ioc.add_argument("--domain", nargs="+", help="Domains to check")
    p_ioc.add_argument("--hash", nargs="+", help="File hashes (MD5 or SHA256)")
    p_ioc.add_argument("--abuseipdb-key", dest="abuseipdb_key", default="")
    p_ioc.add_argument("--vt-key", dest="vt_key", default="")

    # report
    p_rep = sub.add_parser("report", help="Pretty-print a saved JSON report")
    p_rep.add_argument("file", help="Path to JSON report file")

    args = parser.parse_args()

    if args.command == "monitor" or args.command is None:
        if args.command is None:
            # Default: short monitor run
            args.duration = 60
            args.output = "netsentinel_report.json"
        cmd_monitor(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "ioc":
        cmd_ioc(args)
    elif args.command == "report":
        cmd_report(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
