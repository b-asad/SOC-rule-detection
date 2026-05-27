# SEC-ENRG-IM-001 — Energy: Grid / Infrastructure Disruption Indicators

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-ENRG-IM-001` |
| **MITRE Technique** | T1489 — Service Stop / T1490 — Inhibit System Recovery |
| **Sector** | Energy & Utilities |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) · OT Syslog |

## Description
Ransomware or destructive malware precursors on energy infrastructure — shadow copy deletion, service termination targeting EMS/SCADA/DMS processes, or configuration wiping commands. Any of these on energy sector systems represents a potential threat to public safety and must be treated as a Critical National Infrastructure incident.

## Microsoft Sentinel KQL
```kql
// SEC-ENRG-IM-001 | Frequency: 5m | Lookback: 5m
let EnergyHosts = (_GetWatchlist('EnergySystemHosts') | project SearchKey);
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where DeviceName in~ (EnergyHosts)
    or DeviceName has_any ("ems","dms","adms","scada","historian","substation","energy","grid","generation")
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
    or (FileName in~ ("net.exe","sc.exe") and ProcessCommandLine has_any ("ems","dms","scada","historian","energy","opc","dnp3","modbus"))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| extend AlertTitle = strcat("CRITICAL CNI: Energy System Disruption Indicator on ", DeviceName)
| extend EmergencyAction = "Notify Control Room Engineer. Consider manual operation mode."
| extend NIS2Obligation = "NIS2: 24h initial report to NCSC. Notify Ofgem/Ofwat/ONR."
```

## Response Actions
- [ ] Notify Control Room Engineer — can systems go to manual control?
- [ ] Notify CISO and CEO
- [ ] Report to NCSC within 24h (NIS2 Article 23)
- [ ] Notify sector regulator (Ofgem/Ofwat/ONR)
- [ ] Consider notifying CPNI and CISA if US-linked organisation

## References
- [MITRE T1489](https://attack.mitre.org/techniques/T1489/) | [NIS2 Article 23](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555)
