# SEC-ENRG-LM-001 — Energy: IT-to-OT Pivot in Energy Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-ENRG-LM-001` |
| **MITRE Technique** | T1021 — Remote Services |
| **Sector** | Energy & Utilities |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR |
| **Log Source** | `CommonSecurityLog` (OT Firewall) · `AzureNetworkAnalytics_CL` |

## Description
Connection from an IT network host to an OT/SCADA/EMS host in the energy sector — a firewall boundary violation that may indicate an attacker pivoting toward physical infrastructure control. Energy OT networks control power generation, transmission switching, water treatment chemistry, and gas pressure — access enables physical damage or public safety incidents.

## Microsoft Sentinel KQL
```kql
// SEC-ENRG-LM-001 | Frequency: 5m | Lookback: 5m
let OTRanges = (_GetWatchlist('OTNetworkRanges') | project SearchKey);
let ITRanges  = (_GetWatchlist('ITNetworkRanges') | project SearchKey);
let ICSSvcPorts = dynamic([502,4840,44818,20000,102,47808,1911,9600,2404]);
(
    CommonSecurityLog
    | where TimeGenerated >= ago(5m)
    | where DeviceAction !in ("deny","block","drop")
    | where SourceIP has_any (ITRanges) and DestinationIP has_any (OTRanges)
    | extend DetectionType = "IT-to-OT"
)
| union (
    CommonSecurityLog
    | where TimeGenerated >= ago(5m)
    | where DeviceAction !in ("deny","block","drop")
    | where DestinationPort in (ICSSvcPorts)
    | where not(SourceIP has_any (OTRanges))
    | extend DetectionType = "ICS-Protocol-from-IT"
)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, DetectionType
| extend AlertTitle = strcat("ENERGY CNI IT-OT Pivot: ", SourceIP, " -> ", DestinationIP)
| extend PhysicalRisk = "Energy infrastructure control — physical disruption possible"
| extend NIS2Obligation = "NIS2: 24h report to NCSC. Notify Ofgem/Ofwat/ONR."
```

## Response Actions
- [ ] Physical isolation of IT-OT boundary if attacker confirmed in OT network
- [ ] Notify Control Room Engineer and CISO
- [ ] Report to NCSC within 24h (NIS2)
- [ ] Engage CPNI for CNI-specific guidance

## References - [MITRE T1021](https://attack.mitre.org/techniques/T1021/)
