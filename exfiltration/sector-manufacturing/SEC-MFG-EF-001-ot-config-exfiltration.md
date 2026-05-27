# SEC-MFG-EF-001 — Manufacturing: OT Configuration / PLC Code Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-MFG-EF-001` |
| **MITRE Technique** | T1048 — Exfiltration Over Alternative Protocol |
| **Sector** | Manufacturing |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` (MDE) · Firewall logs |

## Description
Exfiltration of OT configuration files, PLC ladder logic, SCADA project files, or HMI screen configurations. These files contain the logic controlling physical production processes — in the hands of an adversary they enable targeted attacks that can cause equipment damage or safety incidents.

## Microsoft Sentinel KQL
```kql
// SEC-MFG-EF-001 | Frequency: 15m | Lookback: 1h
let OTFileTypes = dynamic([".rss",".acd",".csv",".prj",".zap14",".zap15",".mer",".ned",".l5x",".l5k",".st",".fbd",".il",".sfc",".scl"]);
DeviceFileEvents
| where TimeGenerated >= ago(1h)
| where FileName has_any (OTFileTypes)
| where ActionType in ("FileCopied","FileCreated")
| where FolderPath !has_any ("backup","archive","local")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, AccountName
| extend AlertTitle = strcat("OT Config File Accessed: ", FileName)
| extend PhysicalRisk = "PLC/SCADA configuration exfiltration enables targeted physical attack"
```

## Response Actions
- [ ] Isolate the OT engineering workstation
- [ ] Notify OT Security team and CISO
- [ ] Assess which OT systems' configurations are now exposed
- [ ] Consider updating/randomising PLC configurations if exposure confirmed
- [ ] Report under NIS2

## References - [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
