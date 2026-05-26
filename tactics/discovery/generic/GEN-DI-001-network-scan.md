# GEN-DI-001 — Discovery: Internal Network Scanning

| Field | Value |
|-------|-------|
| Rule ID | GEN-DI-001 |
| Tactic | Discovery |
| Technique | T1046 — Network Service Discovery |
| Severity | **Medium** | Priority | **P2** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceNetworkEvents` (MDE), `AzureNetworkAnalytics_CL` |

## Description
A host sends SYN connection attempts to more than 30 unique internal IP addresses within 60 seconds — pattern consistent with port scanning or network enumeration tools (nmap, Masscan, built-in PowerShell scanning).

---

## Microsoft Sentinel KQL
```kql
// GEN-DI-001 | Frequency: 10m | Lookback: 10m
DeviceNetworkEvents
| where TimeGenerated >= ago(10m)
| where ActionType == "ConnectionAttempted"
| where RemoteIP startswith "10." or RemoteIP startswith "192.168." or RemoteIP startswith "172."
| summarize UniqueIPs=dcount(RemoteIP), Ports=make_set(RemotePort,10), First=min(TimeGenerated), Last=max(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(TimeGenerated, 60s)
| where UniqueIPs > 30
| extend ScanRate = UniqueIPs
| order by ScanRate desc
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-DI-001 | Run: Every hour
DeviceNetworkEvents
| where Timestamp >= ago(1h) and ActionType == "ConnectionAttempted"
| where RemoteIP matches regex @"^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\."
| summarize UniqueIPs=dcount(RemoteIP), Ports=make_set(RemotePort) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 60s)
| where UniqueIPs > 30
| order by UniqueIPs desc
```

---

## Investigation Guide

**Step 1:** Identify the scanning process — nmap? PowerShell? An unexpected binary?  
**Step 2:** What IP ranges are being scanned? Are they targeting domain controllers, servers, or entire subnets?  
**Step 3:** Check if this device was recently compromised (correlate with initial access/execution alerts).  
**Step 4 — Attacker's Objective:** Scanning often precedes lateral movement. Check for subsequent RDP/SMB/WinRM connections from this host.

---

## Response Actions
- [ ] If scanning from a workstation: investigate immediately (not normal behaviour)
- [ ] If scanning from a server: verify with IT — may be authorised monitoring
- [ ] Block the scanning process if confirmed malicious
- [ ] Correlate with lateral movement rules (GEN-LM-*)

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Authorised vulnerability scanners | Add scanner IP/hostname to exclusions watchlist |
| Monitoring agents (PRTG, Zabbix) | Add management system IPs to exclusions |

## References
- [MITRE T1046](https://attack.mitre.org/techniques/T1046/)
