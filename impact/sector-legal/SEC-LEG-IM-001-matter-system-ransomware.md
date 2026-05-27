# SEC-LEG-IM-001 — Legal: Ransomware Targeting Matter Management / DMS

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-LEG-IM-001` |
| **MITRE Technique** | T1486 — Data Encrypted for Impact |
| **Sector** | Legal |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |

## Description
Ransomware targeting a law firm's matter management system, DMS, or document repositories. Law firms are consistently targeted due to valuable and irreplaceable client documents and the high reputational pressure to pay ransoms quickly. Under SRA obligations, firms must protect client files.

## Microsoft Sentinel KQL
```kql
// SEC-LEG-IM-001 | Frequency: 5m | Lookback: 5m
let LegalHosts = (_GetWatchlist('LegalSystemHosts') | project SearchKey);
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
| where DeviceName in~ (LegalHosts)
    or DeviceName has_any ("dms","imanage","netdocuments","matter","legal","filesite")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| extend AlertTitle = strcat("Legal DMS Ransomware Indicator: ", DeviceName)
| extend SRAObligation = "SRA: Notify clients if their files are unavailable or at risk"
```

## Response Actions
- [ ] Isolate DMS and matter management servers
- [ ] Notify COLP, Managing Partner, and IT Director
- [ ] Assess client notification requirement — SRA rule 6.3
- [ ] Notify ICO if client personal data encrypted

## References - [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
