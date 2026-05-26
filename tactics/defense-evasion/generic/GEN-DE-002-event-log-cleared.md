# GEN-DE-002 — Defense Evasion: Windows Event Log Cleared

| Field | Value |
|-------|-------|
| Rule ID | GEN-DE-002 |
| Tactic | Defense Evasion |
| Technique | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | Windows Security Event 1102, System Event 104 |

## Description
Windows Security or System event log cleared. Attackers clear logs after compromise to destroy forensic evidence. Legitimate log clearing is extremely rare on Windows. **Treat every instance as an active incident.**

---

## Microsoft Sentinel KQL
```kql
// GEN-DE-002 | Frequency: 5m | Lookback: 5m
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID in (1102, 104)  // 1102 = Security log cleared, 104 = System log cleared
| project TimeGenerated, Computer, Account, Activity, EventID
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-DE-002 | Run: Every hour
DeviceEvents
| where Timestamp >= ago(1h)
| where ActionType == "EventLogCleared"
| project Timestamp, DeviceName, AccountName, AdditionalFields
```

---

## Investigation Guide

**Step 1 — Treat as Active Incident (Immediate)**  
Log clearing typically occurs after data exfiltration or before ransomware deployment.  
Check all other active alerts on this device — correlate the timeline.

**Step 2 — What Was Cleared and By Whom**  
Event 1102 includes the account that cleared the log. Is it a domain admin? A service account?  
Was this during a maintenance window? (Even then, investigate.)

**Step 3 — Check Remaining Logs**  
Defender for Endpoint telemetry is separate from Windows Event Logs — MDE data is preserved even if logs are cleared locally.
```kql
DeviceProcessEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(4h)
| project Timestamp, FileName, ProcessCommandLine, AccountName | order by Timestamp asc
```

---

## Response Actions
- [ ] Treat as P1 — notify SOC Manager and customer
- [ ] MDE telemetry is your primary forensic source now — pull all available data
- [ ] Isolate the device for forensic imaging
- [ ] Open full IR investigation — assume compromise preceded the log clear

## References
- [MITRE T1070.001](https://attack.mitre.org/techniques/T1070/001/)
