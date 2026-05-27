# SEC-ENRG-CO-001 — Energy: Grid Topology / Infrastructure Reconnaissance

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-ENRG-CO-001` |
| **MITRE Technique** | T1046 — Network Service Discovery |
| **Sector** | Energy & Utilities |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceNetworkEvents` (MDE) · OT Firewall logs |

## Description
Systematic scanning or enumeration of OT/ICS network topology — querying SCADA, DMS, or historian hosts for connected devices, network layout, and asset inventory. Nation-state pre-positioning for infrastructure attacks typically begins with extensive network reconnaissance of OT systems.

## Microsoft Sentinel KQL
```kql
// SEC-ENRG-CO-001 | Frequency: 10m | Lookback: 10m
let OTRanges = (_GetWatchlist('OTNetworkRanges') | project SearchKey);
DeviceNetworkEvents
| where TimeGenerated >= ago(10m) and ActionType == "ConnectionAttempted"
| where RemoteIP has_any (OTRanges)
    or RemotePort in (502, 4840, 44818, 20000, 102, 47808, 1911, 9600)
| summarize UniqueTargets=dcount(RemoteIP), Ports=make_set(RemotePort,10)
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 60s)
| where UniqueTargets > 5
| extend AlertTitle = strcat("OT/Energy Network Scan: ", DeviceName, " — ", UniqueTargets, " ICS hosts")
| extend CNIRisk = "Network reconnaissance of CNI OT systems — nation-state pre-positioning risk"
```

## Response Actions
- [ ] Isolate scanning host
- [ ] Notify OT Security team and CISO
- [ ] Report to NCSC if nation-state indicators

## References - [MITRE T1046](https://attack.mitre.org/techniques/T1046/)
