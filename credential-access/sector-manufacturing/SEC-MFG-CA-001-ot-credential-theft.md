# SEC-MFG-CA-001 — Manufacturing: OT Engineering Account Credential Access

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-MFG-CA-001` |
| **MITRE Technique** | T1003.001 — LSASS Memory |
| **Sector** | Manufacturing |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceEvents` (MDE) |

## Description
LSASS memory access on an OT engineering workstation or jump server. Credentials from OT engineering hosts typically include domain accounts with access to PLC programming software, SCADA historian, and OT network management. Any credential dump from these hosts carries a physical safety risk.

## Microsoft Sentinel KQL
```kql
// SEC-MFG-CA-001 | Frequency: 5m | Lookback: 5m
let OTEngHosts = (_GetWatchlist('OTEngineeringHosts') | project SearchKey);
let Approved = dynamic(["MsMpEng.exe","SenseCE.exe","csrss.exe","wininit.exe"]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (Approved))
| where DeviceName in~ (OTEngHosts)
    or DeviceName has_any ("ot","scada","hmi","plc","engineering","historian","jump","bastion")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| extend AlertTitle = strcat("OT Host LSASS Dump — CRITICAL: ", DeviceName)
| extend OTSafetyRisk = "OT engineering credentials exposed — physical equipment risk"
| extend NIS2Obligation = "NIS2: Report to NCSC within 24h"
```

## Response Actions
- [ ] Isolate OT engineering workstation — MDE
- [ ] Revoke OT network access for the exposed accounts
- [ ] Notify OT Security team and plant manager
- [ ] Reset all exposed account passwords — including OT-specific credentials
- [ ] Report to NCSC under NIS2 if OT systems at risk

## References - [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
