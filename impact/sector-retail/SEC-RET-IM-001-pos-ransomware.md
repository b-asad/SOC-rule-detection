# SEC-RET-IM-001 — Retail: Ransomware Targeting POS / Store Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-IM-001` |
| **MITRE Technique** | T1486 — Data Encrypted for Impact |
| **Sector** | Retail |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |

## Description
Ransomware precursor activity on retail infrastructure — POS terminals, store servers, inventory systems. Retail ransomware can halt card payment processing across all stores within hours, causing significant revenue loss and reputational damage. PCI DSS notification obligations apply if cardholder data is at risk.

## Microsoft Sentinel KQL
```kql
// SEC-RET-IM-001 | Frequency: 5m | Lookback: 5m
let POSHosts = (_GetWatchlist('POS-Hosts') | project SearchKey);
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
| where DeviceName in~ (POSHosts)
    or DeviceName has_any ("pos","till","register","checkout","kiosk","store","branch","retail")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| extend AlertTitle = strcat("Retail Ransomware Indicator: ", DeviceName)
| extend TradingImpact = "Stores may be unable to process card payments. Activate cash fallback."
| extend PCIObligation = "PCI DSS 12.10.5: Notify acquiring bank if CHD systems affected"
```

## Response Actions
- [ ] Isolate affected store systems — MDE
- [ ] Notify Store Operations Director — activate cash-only fallback
- [ ] Notify acquiring bank if POS in CDE scope
- [ ] Assess whether store network segments can be isolated to contain spread

## References - [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
