# GEN-CC-001 — C2 Beaconing: Periodic Outbound HTTP/S

| Field | Value |
|-------|-------|
| Rule ID | GEN-CC-001 |
| Tactic | Command and Control |
| Technique | T1071.001 — Application Layer Protocol: Web Protocols |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `CommonSecurityLog` (Firewall/Proxy), `DeviceNetworkEvents` (MDE) |

## Description
Periodic outbound HTTP/HTTPS connections to the same external IP with consistent intervals and low jitter — characteristic of C2 beaconing. Legitimate apps have variable timing; C2 malware maintains consistent sleep cycles.

---

## Microsoft Sentinel KQL
```kql
// GEN-CC-001 | Frequency: 15m | Lookback: 2h
let Exclusions = dynamic(["microsoft.com","windowsupdate.com","office.com","live.com","azure.com","office365.com","google.com","gstatic.com","akamai.com","cloudflare.com"]);
CommonSecurityLog
| where TimeGenerated >= ago(2h)
| where DeviceAction !in ("deny","block","drop")
| where DestinationPort in (80,443,8080,8443)
| where not(DestinationHostName has_any (Exclusions))
| where DestinationIP !startswith "10." and DestinationIP !startswith "192.168." and DestinationIP !startswith "172."
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName, DestinationPort, DeviceName
| sort by SourceIP asc, DestinationIP asc, TimeGenerated asc
| serialize
| extend PrevTime=prev(TimeGenerated,1), PrevSrc=prev(SourceIP,1), PrevDst=prev(DestinationIP,1)
| where SourceIP==PrevSrc and DestinationIP==PrevDst
| extend IntervalSec=datetime_diff('second',TimeGenerated,PrevTime)
| where IntervalSec > 30
| summarize Count=count(), AvgInterval=avg(IntervalSec), StdDev=stdev(IntervalSec), First=min(TimeGenerated), Last=max(TimeGenerated)
    by SourceIP, DestinationIP, DestinationHostName, DestinationPort, DeviceName
| where Count >= 10 and StdDev <= 30
| extend BeaconScore=round(100.0-(StdDev/AvgInterval*100),1)
| order by BeaconScore desc
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-CC-001 | Run: Every hour
let Excl=dynamic(["microsoft.com","windowsupdate.com","office.com","azure.com","google.com"]);
DeviceNetworkEvents
| where Timestamp >= ago(2h) and ActionType=="ConnectionSuccess"
| where RemotePort in (80,443,8080,8443)
| where not(RemoteUrl has_any (Excl))
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| serialize
| extend PrevTime=prev(Timestamp,1), PrevDev=prev(DeviceName,1), PrevDst=prev(RemoteIP,1)
| where DeviceName==PrevDev and RemoteIP==PrevDst
| extend IntervalSec=datetime_diff('second',Timestamp,PrevTime)
| where IntervalSec > 30
| summarize Count=count(), AvgInterval=avg(IntervalSec), StdDev=stdev(IntervalSec), Procs=make_set(InitiatingProcessFileName)
    by DeviceName, RemoteIP, RemoteUrl, RemotePort
| where Count >= 8 and StdDev <= 30
| order by StdDev asc
```

---

## Defender for Endpoint — Network Investigation
```kql
// Identify the process making beaconing connections
DeviceNetworkEvents
| where DeviceName == "<DEVICE>" | where RemoteIP == "<C2_IP>" | where Timestamp >= ago(2h)
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessFolderPath, RemoteUrl, RemotePort
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Reputation Check (< 10 min)**  
Submit destination IP and domain to VirusTotal, Shodan, AlienVault OTX, AbuseIPDB.  
Check WHOIS: domain age < 30 days = high suspicion.  
Check TLS cert: self-signed on a residential IP = red flag.

**Step 2 — Process Identification (10–20 min)**  
Run the MDE network investigation query above.  
Suspicious: process in `%TEMP%`, unsigned, masquerading as a legitimate binary.

**Step 3 — Traffic Content (20–35 min)**  
Review HTTP request/response: consistent URI, minimal data = check-in with no tasking.  
POST bodies with base64/encoded data = active C2 with tasking.

**Step 4 — Persistence Check (35–50 min)**
```kql
DeviceRegistryEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where RegistryKey has_any ("CurrentVersion\\Run","CurrentVersion\\RunOnce","Services","Scheduled")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

---

## Response Actions
- [ ] Block destination IP and domain — Sentinel TI watchlist + firewall
- [ ] Isolate device if process confirmed malicious
- [ ] Submit process hash to Microsoft MDTI
- [ ] Search same C2 across all customer environments
- [ ] Run full malware scan + memory forensics

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| NTP, telemetry agents, monitoring heartbeats | Add known agent C2 endpoints to Exclusions watchlist |
| Teams / Zoom heartbeats | Add to Exclusions list |

## References
- [MITRE T1071.001](https://attack.mitre.org/techniques/T1071/001/)
