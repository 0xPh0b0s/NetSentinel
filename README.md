# NetSentinel — Passive Network Threat Intelligence Engine

A Proof of concept, zero-dependency-on-root passive network monitor that detects real threats
using behavioral analysis, heuristics, and MITRE ATT&CK mapping.

---

## What It Detects

| Threat                     | MITRE Technique              | Severity |
|----------------------------|------------------------------|----------|
| Suspicious port connections | T1571 – Non-Standard Port   | HIGH     |
| Port scan activity          | T1046 – Network Discovery   | HIGH     |
| Lateral movement attempts   | T1021 – Remote Services     | CRITICAL |
| DNS tunneling / hijack      | T1071.004 – DNS             | MEDIUM   |
| Tor network usage           | T1090.003 – Multi-hop Proxy | HIGH     |
| C2 beaconing patterns       | T1071 – App Layer Protocol  | MEDIUM   |
| Suspicious process spawning | T1059 – Scripting Interp.   | CRITICAL |
| ARP cache poisoning         | T1557.002 – ARP Poisoning   | CRITICAL |
| High-volume data exfiltration | T1048 – Exfil Alt Protocol | HIGH    |

---

## Quick Start

```bash
# Install dependencies
pip install rich psutil requests

# Run a 60-second analysis (default)
python3 netsentinel.py

# Run for 5 minutes with custom report path
python3 netsentinel.py -d 300 -o my_report.json

# Stop early with Ctrl+C — report still saves
```

---

## Output

**Live Dashboard** (terminal, refreshes every 2 seconds):
- Color-coded threat events with MITRE mappings
- Active connections (flagging external IPs in cyan)
- Listening ports (flagging risky ones in red)
- System CPU/memory/network error metrics
- Elapsed timer and threat severity counters

**JSON Report** (`netsentinel_report.json`):
```json
{
  "report_metadata": { "hostname": "...", "generated_at": "...", ... },
  "executive_summary": {
    "total_threats": 3,
    "by_severity": { "HIGH": 2, "MEDIUM": 1 },
    "risk_level": "HIGH"
  },
  "threat_events": [...],
  "network_state": { "active_connections": [...], "listening_ports": [...] },
  "recommendations": [...]
}
```

---

## Architecture

```
netsentinel.py
├── ThreatIntelEngine     # All detection logic (pure Python, heuristic-based)
│   ├── check_suspicious_port()
│   ├── check_port_scan_victim()
│   ├── check_lateral_movement()
│   ├── check_dns_anomaly()
│   ├── check_beaconing()
│   ├── check_tor_usage()
│   ├── check_unusual_parent()
│   └── check_data_exfil_volume()
│
├── NetworkCollector      # psutil-based live network state collection
│   ├── get_connections()
│   ├── get_listening_ports()
│   ├── get_arp_table()
│   ├── check_arp_spoofing()
│   └── get_system_metrics()
│
├── Dashboard             # Rich terminal UI — live, color-coded
│
└── ReportGenerator       # Structured JSON threat intelligence reports
```

---

## No Root Required

NetSentinel uses **psutil** for connection inspection — no raw packet capture.
This means it runs without `sudo` on most systems, making it safe and portable.

For ARP spoofing detection, it calls `arp -a` which is available on all platforms.

---

## Extending NetSentinel

Add a new detection rule in `ThreatIntelEngine`:

```python
def check_my_new_threat(self, connections):
    events = []
    for c in connections:
        if <your_condition>:
            events.append(ThreatEvent(
                timestamp=datetime.now().isoformat(),
                threat_type="MY_THREAT",
                severity="HIGH",
                source_ip=c.local_addr,
                dest_ip=c.remote_addr,
                port=c.remote_port,
                description="...",
                mitre_tactic="...",
                mitre_technique="T1XXX – ...",
            ))
    return events
```

Then add a call to it in `NetSentinel.run()`.

---

## Disclaimer

NetSentinel is for authorized security monitoring only.
Use only on networks and systems you own or have explicit permission to monitor.
Credits reserved to 0xNullVector
