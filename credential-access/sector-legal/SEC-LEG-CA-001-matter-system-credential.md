# SEC-LEG-CA-001 — Legal: Legal Matter System Credential Access

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-LEG-CA-001` |
| **MITRE Technique** | T1003.001 — LSASS Memory |
| **Sector** | Legal |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceEvents` (MDE) |

## Description
LSASS dump on a host running legal matter management, DMS, or document review platforms (iManage, NetDocuments, Clio, Aderant). Credentials from these systems give access to privileged legal communications, client files, and trust account access — potentially all legally privileged.

## Microsoft Sentinel KQL
```kql
// SEC-LEG-CA-001 | Frequency: 5m | Lookback: 5m
let LegalHosts = (_GetWatchlist('LegalSystemHosts') | project SearchKey);
let Approved = dynamic(["MsMpEng.exe","SenseCE.exe","csrss.exe","wininit.exe"]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (Approved))
| where DeviceName in~ (LegalHosts)
    or DeviceName has_any ("dms","imanage","netdocuments","clio","matter","legal","fee-earner")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessSHA256
| extend AlertTitle = strcat("Legal System LSASS Dump: ", DeviceName)
| extend PrivilegeRisk = "Credentials may provide access to legally privileged communications"
```

## Response Actions
- [ ] Isolate device — MDE
- [ ] Reset all account passwords exposed on the host
- [ ] Notify COLP and DPO
- [ ] Assess if client privileged data was accessible via the compromised credentials

## References - [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
