# SEC-FS-IM-001 — Financial Services: Payment/Banking System Disruption

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-FS-IM-001` |
| **MITRE Technique** | T1489 — Service Stop |
| **Sector** | Financial Services |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |
| **Sector Context** | Core banking systems, SWIFT infrastructure, payment gateways, clearing systems |

## Description
Critical financial services process termination — stopping payment gateway, core banking, SWIFT, or clearing system services. Attackers target financial services infrastructure to cause operational disruption, force ransom payments, or cover fraud transactions. Under DORA (Digital Operational Resilience Act) and FCA PS21/3, financial firms must report significant operational disruptions.

## Microsoft Sentinel KQL
```kql
// SEC-FS-IM-001 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where FileName in~ ("net.exe","sc.exe","taskkill.exe")
| where ProcessCommandLine has_any (
    "swift","SWIFT","payment","clearing","settlement","core banking","temenos","finacle",
    "flexcube","misys","finastra","mambu","FIS","oracle financials","CHAPS","BACS","Faster Payments"
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
| extend AlertTitle = strcat("Financial System Service Termination on ", DeviceName)
| extend DORAObligation = "DORA Art.19: Report major ICT incidents to FCA/PRA within 4h"
```

## Response Actions
- [ ] Identify which payment system was stopped and whether it can be restarted safely
- [ ] Notify CTO, CISO, and Head of Operations
- [ ] Assess FCA/PRA notification obligation under DORA (4h window for major ICT incidents)
- [ ] Activate financial services BCP — can payments be rerouted?

## References
- [MITRE T1489](https://attack.mitre.org/techniques/T1489/) | [DORA Article 19](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554)
