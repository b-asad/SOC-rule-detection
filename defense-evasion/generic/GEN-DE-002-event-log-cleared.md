# GEN-DE-002 — Defense Evasion: Windows Event Log Cleared

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DE-002` |
| **MITRE Technique** | T1070.001 — Clear Windows Event Logs |
| **Sector** | Generic |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | Windows Security Event 1102 · System Event 104 |

## Description
Windows Security (Event 1102) or System (Event 104) log cleared. Attackers clear logs after compromise to destroy evidence. Legitimate log clearing on Windows is extremely rare. Every instance must be treated as an active incident — MDE telemetry is preserved independently of Windows Event Logs and should be used as the primary forensic source.

## Microsoft Sentinel KQL
```kql
// GEN-DE-002 | Frequency: 5m | Lookback: 5m | Threshold: > 0
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID in (1102, 104)
| project TimeGenerated, Computer, Account, Activity, EventID
| extend AlertTitle = strcat("Event Log Cleared on ", Computer, " by ", Account)
| extend Severity = "Critical"
| extend ForensicNote = "MDE telemetry preserved independently — use DeviceProcessEvents as primary forensic source"
```

## Defender XDR — Advanced Hunting
```kql
// GEN-DE-002 | Run: Every hour
DeviceEvents
| where Timestamp >= ago(1h) and ActionType == "EventLogCleared"
| project Timestamp, DeviceName, AccountName, AdditionalFields
```

## Investigation Guide
**Step 1 (Immediate):** Log clearing typically follows data exfiltration or precedes ransomware. Check all other open alerts on this device. Correlate the exact clear time with the MDE process timeline.
**Step 2 (< 15 min):** Who cleared the log? Is the account a domain admin or a service account that shouldn't have this right?
**Step 3 (15–40 min):** Use MDE telemetry (unaffected by log clearing) to reconstruct activity:
```kql
DeviceProcessEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(4h)
| project Timestamp, FileName, ProcessCommandLine, AccountName, SHA256
| order by Timestamp asc
```

## Response Actions
- [ ] Treat as P1 — notify SOC Manager and customer
- [ ] MDE telemetry is now the primary forensic source — pull all available data immediately
- [ ] Isolate device for forensic imaging
- [ ] Open full IR investigation — assume compromise preceded the log clear

## References - [MITRE T1070.001](https://attack.mitre.org/techniques/T1070/001/)
