# GEN-DI-001 — Discovery: Internal Network Scanning

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DI-001` |
| **MITRE Technique** | T1046 — Network Service Discovery |
| **Sector** | Generic |
| **Severity** | **Medium** | **Priority** | **P2** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceNetworkEvents` (MDE) · `AzureNetworkAnalytics_CL` |

## Description
A host sends connection attempts to more than 30 unique internal IPs within a 60-second window — consistent with automated port scanning or network enumeration. Scanning typically precedes lateral movement. On workstations this is almost always malicious; on servers verify against known monitoring tools.

## Microsoft Sentinel KQL
```kql
// GEN-DI-001 | Frequency: 10m | Lookback: 10m
DeviceNetworkEvents
| where TimeGenerated >= ago(10m)
| where ActionType == "ConnectionAttempted"
| where RemoteIP startswith "10." or RemoteIP startswith "192.168." or RemoteIP startswith "172."
| summarize UniqueIPs=dcount(RemoteIP), Ports=make_set(RemotePort,10)
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 60s)
| where UniqueIPs > 30
| extend AlertTitle = strcat("Network Scan: ", DeviceName, " contacted ", UniqueIPs, " internal IPs in 60s")
```

## Defender XDR — Advanced Hunting
```kql
// GEN-DI-001 | Run: Every hour
DeviceNetworkEvents
| where Timestamp >= ago(1h) and ActionType == "ConnectionAttempted"
| where RemoteIP matches regex @"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
| summarize UniqueIPs=dcount(RemoteIP), Ports=make_set(RemotePort,5)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 60s)
| where UniqueIPs > 30
| order by UniqueIPs desc
```

## Investigation Guide
**Step 1:** Is scanning from a workstation? → Almost certainly malicious. From a server? → Verify against monitoring tool inventory.
**Step 2:** What ports are being scanned? 445 (SMB), 3389 (RDP), 22 (SSH) = attacker looking for lateral movement targets.
**Step 3:** Check for subsequent successful connections from this host (lateral movement):
```kql
DeviceNetworkEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (445, 3389, 22, 5985, 5986)
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
```

## Response Actions
- [ ] If scanning from workstation: investigate immediately as compromised host
- [ ] Block the scanning process if malicious
- [ ] Correlate with lateral movement alerts (GEN-LM-001)

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Authorised vulnerability scanner (Nessus, Qualys) | Add scanner IP to discovery exclusions watchlist |
| Network monitoring agents (PRTG, Zabbix, SolarWinds) | Exclude management server IP/hostname |

## References - [MITRE T1046](https://attack.mitre.org/techniques/T1046/)
