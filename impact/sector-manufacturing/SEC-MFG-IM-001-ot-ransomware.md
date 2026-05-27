# SEC-MFG-IM-001 — Manufacturing: Ransomware Impacting Production Systems

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-MFG-IM-001` |
| **MITRE Technique** | T1486 — Data Encrypted for Impact |
| **Sector** | Manufacturing |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` · `DeviceFileEvents` (MDE) |

## Description
Ransomware targeting manufacturing plant IT systems. Even if OT systems are airgapped, ransomware on IT systems can halt production by disrupting ERP, MES (Manufacturing Execution Systems), supply chain, and quality management systems. Production downtime costs typically exceed the ransom demand significantly.

## Microsoft Sentinel KQL
```kql
// SEC-MFG-IM-001 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
| join kind=leftouter (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where ProcessCommandLine has_any ("mes","erp","sap","oracle","infor","epicor","production","manufacturing")
    | project DeviceName, ProdSystem=ProcessCommandLine
) on DeviceName
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, ProdSystem
| extend AlertTitle = strcat("Manufacturing Ransomware: ", DeviceName)
| extend ProductionRisk = "Assess production line shutdown and supply chain impact"
| extend NIS2Obligation = "NIS2: Report within 24h if production classified as critical infrastructure"
```

## Response Actions
- [ ] Isolate affected systems — MDE
- [ ] Notify Plant Manager and Production Director
- [ ] Assess production impact — which lines can continue on manual fallback?
- [ ] Notify supply chain partners if delivery commitments affected
- [ ] Report under NIS2 if applicable

## References - [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
