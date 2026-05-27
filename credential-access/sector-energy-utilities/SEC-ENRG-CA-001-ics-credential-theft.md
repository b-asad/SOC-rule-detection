# SEC-ENRG-CA-001 — Energy & Utilities: ICS Engineering Credential Theft

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-ENRG-CA-001` |
| **MITRE Technique** | T1003.001 — LSASS Memory |
| **Sector** | Energy & Utilities |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceEvents` (MDE) |
| **Sector Context** | Power generation, transmission, water treatment, gas networks |

## Description
LSASS memory access on a host with access to energy management, SCADA, or grid management systems. Nation-state actors (VOLTZITE/Volt Typhoon, Sandworm) specifically target energy sector credentials to pre-position for disruption of power grids or water systems. This is a **critical national infrastructure** event requiring immediate NCSC notification.

## Microsoft Sentinel KQL
```kql
// SEC-ENRG-CA-001 | Frequency: 5m | Lookback: 5m
let EnergyHosts = (_GetWatchlist('EnergySystemHosts') | project SearchKey);
let Approved = dynamic(["MsMpEng.exe","SenseCE.exe","csrss.exe","wininit.exe"]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (Approved))
| where DeviceName in~ (EnergyHosts)
    or DeviceName has_any ("ems","dms","adms","scada","historian","substation","control-room","grid","generation","turbine")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessSHA256
| extend AlertTitle = strcat("ENERGY CNI: LSASS Dump on ", DeviceName)
| extend CNIRisk = "Critical National Infrastructure — physical disruption possible"
| extend NIS2Obligation = "NIS2: Report to NCSC within 24h. Notify Ofgem/Ofwat."
```

## Response Actions
- [ ] Isolate device — MDE (verify isolation does not disrupt live control systems)
- [ ] Notify CISO and Control Room Engineer simultaneously
- [ ] Revoke OT network access for exposed accounts
- [ ] Report to NCSC within 24h
- [ ] Notify Ofgem/Ofwat sector regulator

## References
- [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/) | [NIS2](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555)
