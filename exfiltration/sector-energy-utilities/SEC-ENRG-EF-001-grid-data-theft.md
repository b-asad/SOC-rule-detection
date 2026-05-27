# SEC-ENRG-EF-001 — Energy: Grid Configuration / Operational Data Theft

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-ENRG-EF-001` |
| **MITRE Technique** | T1048 — Exfiltration Over Alternative Protocol |
| **Sector** | Energy & Utilities |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` (MDE) · Firewall logs |

## Description
Exfiltration of grid topology maps, substation configuration files, energy management system databases, or operational data. This intelligence enables adversaries to understand system interdependencies and plan targeted disruption attacks against critical points in national infrastructure.

## Microsoft Sentinel KQL
```kql
// SEC-ENRG-EF-001 | Frequency: 15m | Lookback: 1h
let EnergyFileTypes = dynamic([".rdb",".rtu",".dnp",".csv",".mdb",".accdb",".historian",".cim",".xml"]);
let OTHosts = (_GetWatchlist('EnergySystemHosts') | project SearchKey);
DeviceFileEvents
| where TimeGenerated >= ago(1h)
| where DeviceName in~ (OTHosts)
    or DeviceName has_any ("ems","dms","historian","scada","substation","grid")
| where FileName has_any (EnergyFileTypes)
    or FileName has_any ("topology","grid","substation","feeder","generation","dispatch","network_model","CIM")
| where ActionType in ("FileCopied","FileCreated")
| where FolderPath !has_any ("backup","archive","local")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, AccountName
| extend AlertTitle = strcat("Grid Data Exfiltration: ", FileName)
| extend CNIRisk = "Grid topology intelligence enables targeted infrastructure attack"
```

## Response Actions
- [ ] Isolate the system exfiltrating data
- [ ] Notify CISO and Control Room management
- [ ] Report to NCSC (NIS2 Article 23)
- [ ] Assess whether exposed data enables a targeted attack — consider network topology changes

## References - [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
