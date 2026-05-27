# GEN-EF-002 — Exfiltration: Data Exfiltration Over C2 Channel

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EF-002` |
| **MITRE Tactic** | Exfiltration |
| **MITRE Technique** | T1041 — Exfiltration Over C2 Channel |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceNetworkEvents` (MDE) · `CommonSecurityLog` (Firewall) |
| **Created** | May 2026 |

---

## Description

Large volumes of data sent outbound via the same connection used for C2 beaconing — indicating the attacker is exfiltrating data through their established C2 channel rather than a separate protocol. Indicators: existing beaconing session (GEN-CC-001) with dramatically increased outbound bytes in a short window.

---

## Microsoft Sentinel KQL

```kql
// GEN-EF-002 | Frequency: 15m | Lookback: 2h
// Correlate: host with active C2 beaconing suddenly sending large data volumes
let BeaconingHosts = (
    CommonSecurityLog
    | where TimeGenerated >= ago(2h)
    | where DeviceAction !in ("deny","block","drop")
    | where DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
    | summarize AvgBytes=avg(SentBytes), StdDev=stdev(SentBytes), ConnCount=count()
        by SourceIP, DestinationIP
    | where ConnCount >= 5 and StdDev <= 30  // Beaconing pattern
);
CommonSecurityLog
| where TimeGenerated >= ago(15m)
| where DeviceAction !in ("deny","block","drop")
| where DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
| summarize RecentBytes=sum(SentBytes) by SourceIP, DestinationIP, DeviceName
| join kind=inner BeaconingHosts on SourceIP, DestinationIP
| where RecentBytes > (AvgBytes + 10 * StdDev)  // Spike above normal beacon size
| where RecentBytes > 1000000  // > 1MB
| extend AlertTitle = strcat("Exfil via C2: ", SourceIP, " → ", DestinationIP, " (", RecentBytes / 1048576, " MB)")
```

---

## Investigation Guide

**Step 1:** Correlate with GEN-CC-001 — was this host already flagged for beaconing?
**Step 2:** What data volume was sent? Calculate approximate records if field type is known.
**Step 3:** Submit C2 IP/domain to VirusTotal and threat intel — identify the malware family.

---

## Response Actions
- [ ] Block C2 IP/domain at firewall immediately
- [ ] Isolate the device
- [ ] Identify what data was in the exfiltrated payload (memory forensics)
- [ ] Assess breach notification obligations

## References - [MITRE T1041](https://attack.mitre.org/techniques/T1041/)
