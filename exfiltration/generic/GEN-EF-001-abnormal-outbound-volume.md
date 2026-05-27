# GEN-EF-001 — Exfiltration: Abnormal Outbound Data Volume

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EF-001` |
| **MITRE Technique** | T1048 — Exfiltration Over Alternative Protocol |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `CommonSecurityLog` (Firewall) · `CloudAppEvents` (MCAS) |

## Description
A host transmits significantly more outbound data than its 30-day baseline — a statistical indicator of data staging and exfiltration. Complements cloud-based detection via MCAS anomaly policies. Most reliable when firewall byte-count data is available in Sentinel.

## Microsoft Sentinel KQL
```kql
// GEN-EF-001 | Frequency: 1h | Lookback: 25h
// Compares last hour against 30-day hourly average
let Baseline = (
    CommonSecurityLog
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where DeviceAction !in ("deny","block","drop")
    | where DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
    | summarize AvgHourlyBytes=avg(SentBytes), StdDev=stdev(SentBytes)
        by SourceIP
);
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where DeviceAction !in ("deny","block","drop")
| where DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
| summarize RecentBytes=sum(SentBytes) by SourceIP, DeviceName
| join kind=inner Baseline on SourceIP
| where RecentBytes > (AvgHourlyBytes + 4 * StdDev)
| where AvgHourlyBytes > 0
| extend AnomalyRatio = round(RecentBytes / AvgHourlyBytes, 1)
| where AnomalyRatio > 5
| project SourceIP, DeviceName, RecentBytes, AvgHourlyBytes, AnomalyRatio
| order by AnomalyRatio desc
```

## Defender for Cloud Apps
Enable: **Unusual file download** and **Mass download by a single user** anomaly policies.

## Investigation Guide
**Step 1 (< 10 min):** What is the destination IP/domain? Submit to VirusTotal. Cloud storage? Unknown server?
**Step 2 (10–25 min):** Identify the process sending the data:
```kql
DeviceNetworkEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where RemoteIP == "<DEST_IP>"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, BytesSent
| order by BytesSent desc
```
**Step 3 (25–40 min):** What files were staged or copied before transfer? Check DeviceFileEvents.
**Step 4:** Assess GDPR breach notification — was personal data involved?

## Response Actions
- [ ] Block destination IP/domain at firewall and Sentinel TI watchlist
- [ ] Identify and inventory all transferred files
- [ ] Notify customer DPO if personal data involved — ICO 72h clock
- [ ] Preserve transfer logs as forensic evidence

## References - [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
