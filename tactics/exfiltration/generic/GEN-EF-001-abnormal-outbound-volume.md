# GEN-EF-001 — Exfiltration: Abnormal Outbound Data Volume

| Field | Value |
|-------|-------|
| Rule ID | GEN-EF-001 |
| Tactic | Exfiltration |
| Technique | T1048 — Exfiltration Over Alternative Protocol |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Cloud Apps |
| Log Source | `CommonSecurityLog` (Firewall), `AzureNetworkAnalytics_CL`, `CloudAppEvents` |

## Description
Host transmits significantly more outbound data than its 30-day baseline (> 3 standard deviations). Indicates potential data staging and exfiltration — either via direct network transfer, cloud storage upload, or C2 channel.

---

## Microsoft Sentinel KQL
```kql
// GEN-EF-001 | Frequency: 15m | Lookback: 24h
// Build baseline and detect anomalies in single pass
let Threshold = 3.0;  // Standard deviations above baseline
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where DeviceAction !in ("deny","block","drop")
| where DestinationIP !startswith "10." and DestinationIP !startswith "192.168." and DestinationIP !startswith "172."
| summarize DailyBytes=sum(SentBytes) by SourceIP, bin(TimeGenerated, 1h)
| summarize AvgBytes=avg(DailyBytes), StdDev=stdev(DailyBytes), RecentBytes=max(DailyBytes) by SourceIP
| where RecentBytes > (AvgBytes + Threshold * StdDev)
| where AvgBytes > 0
| extend AnomalyRatio = round(RecentBytes / AvgBytes, 1)
| where AnomalyRatio > 5
| order by AnomalyRatio desc
```

---

## Defender for Cloud Apps — CASB Anomaly Policy
Enable: **Unusual file download** and **Mass download by a single user** anomaly detection policies.  
Customize: Set sensitivity to match customer risk tolerance.

---

## Investigation Guide

**Step 1 — Identify Destination (< 10 min)**  
What is the destination IP/domain? Cloud storage? Unknown server? Threat intel reputation check.

**Step 2 — Source Process**
```kql
DeviceNetworkEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where RemoteIP == "<DEST_IP>"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemotePort, BytesSent
| order by BytesSent desc
```

**Step 3 — Files Transferred**
```kql
DeviceFileEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where ActionType in ("FileCreated","FileCopied") | where FolderPath has_any ("Temp","Staging","AppData")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

---

## Response Actions
- [ ] Block destination IP/domain at firewall and Sentinel TI watchlist
- [ ] Identify and inventory all transferred files
- [ ] Assess GDPR/UK GDPR breach notification obligation (personal data involved?)
- [ ] Notify customer data owner
- [ ] Preserve transfer logs for forensic evidence

## References
- [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
