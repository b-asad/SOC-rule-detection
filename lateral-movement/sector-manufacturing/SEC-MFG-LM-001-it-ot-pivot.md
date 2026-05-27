# SEC-MFG-LM-001 — Manufacturing: IT-to-OT Network Pivot Attempt

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-MFG-LM-001` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | T1021 — Remote Services |
| **Sector** | **Manufacturing** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceNetworkEvents` (MDE) · `AzureNetworkAnalytics_CL` (NSG flow logs) · Firewall/NDR logs |
| **Sector Context** | Manufacturing plants, industrial control systems, SCADA, PLCs, HMIs, OT networks |
| **Created** | May 2026 |

---

## Description

Detects network connections originating from IT network hosts toward OT (Operational Technology) network segments, or direct attempts to connect to industrial control system components (PLCs, HMIs, SCADA servers) using protocols common in manufacturing environments (Modbus TCP port 502, DNP3 port 20000, EtherNet/IP port 44818, OPC port 135, RDP port 3389 to ICS hosts).

An IT-to-OT pivot by an attacker could enable physical damage to manufacturing equipment, production line disruption, or safety system interference. Nation-state actors (Sandworm/Voodoo Bear, Triton/TRISIS threat actor) specifically target OT environments.

**Regulatory:** NIS2 Directive — incidents affecting OT systems must be reported within 24 hours. HSE notification if safety systems are affected.

---

## Microsoft Sentinel KQL

```kql
// SEC-MFG-LM-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
// Requires OT network CIDR ranges in OTNetworkRanges watchlist
// Requires IT/DMZ network CIDR ranges in ITNetworkRanges watchlist
let OTRanges  = (_GetWatchlist('OTNetworkRanges') | project SearchKey);
let ITRanges  = (_GetWatchlist('ITNetworkRanges') | project SearchKey);
let OT_Ports  = dynamic([502, 20000, 44818, 102, 2404, 47808, 9600, 1911, 4840, 34980]);
// Detection 1: IT host connecting to OT subnet (any port)
let IT_to_OT_General = (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(5m)
    | where DeviceName has_any (ITRanges) or RemoteIP has_any (OTRanges)
    | where RemoteIP has_any (OTRanges)
    | where ActionType in ("ConnectionSuccess","ConnectionAttempted")
    | project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
    | extend DetectionType = "IT-to-OT-Network-Access"
);
// Detection 2: Industrial protocol connections from IT hosts
let ICS_Protocol = (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(5m)
    | where RemotePort in (OT_Ports)
    | where not(DeviceName has_any (OTRanges))
    | project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
    | extend DetectionType = "ICS-Protocol-from-IT-Host"
);
// Detection 3: RDP/SSH to known ICS hosts
let RDP_to_ICS = (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(5m)
    | where RemotePort in (3389, 22)
    | where RemoteIP has_any (OTRanges)
    | where not(DeviceName has_any ("jump","bastion","gateway","remote-access"))
    | project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
    | extend DetectionType = "RDP-SSH-to-OT-Host"
);
IT_to_OT_General | union ICS_Protocol | union RDP_to_ICS
| extend AlertTitle = strcat("IT-to-OT Pivot Attempt from ", DeviceName)
| extend SafetyRisk = "Physical equipment damage or safety system interference possible"
| extend NIS2Obligation = "NIS2: Report to NCSC within 24h if OT systems confirmed affected"
| extend HSEObligation = "Notify HSE if safety instrumented systems (SIS) affected"
```

---

## Investigation Guide

**Step 1 — Plant Safety Assessment (Immediate, parallel to investigation)**
Alert the Plant/Site Manager and OT Engineering team simultaneously:
- Are there active industrial processes that could be disrupted?
- Are safety instrumented systems (SIS, ESD systems, BPCS) on the affected network?
- Can the IT-OT boundary be physically isolated if needed?

**Step 2 — Source Host Investigation (< 15 min)**
What is the source IT device? Run full process analysis on it.
Was this device recently compromised (check for GEN-IA-001, GEN-CA-001, GEN-EX-001 alerts)?
The IT host is almost certainly the attacker's pivot point.

**Step 3 — OT Host Impact (15–30 min)**
What is the destination OT host?
- PLC (Programmable Logic Controller) → direct physical process control risk
- HMI (Human-Machine Interface) → operator visibility and control risk
- SCADA server → broad industrial process visibility and control risk
- Engineering workstation → configuration and programming risk

**Step 4 — OT Network Forensics (30–60 min)**
Engage the OT/ICS security specialist. Standard IT forensics tools must NOT be run on live OT systems — they can cause process disruption.

---

## Response Actions
**Immediate**
- [ ] Isolate the source IT host — MDE
- [ ] Physically isolate IT-OT boundary if attacker has reached OT network
- [ ] Notify Plant/Site Manager and OT Engineering team
- [ ] Do NOT use standard IT forensic tools on live OT systems without OT security specialist

**Regulatory**
- [ ] Report to NCSC within 24h (NIS2 / NIS Regulations 2018)
- [ ] Notify HSE if safety systems affected
- [ ] Notify sector regulator if applicable

## References
- [MITRE T1021](https://attack.mitre.org/techniques/T1021/)
- [ICS-CERT: OT security alerts](https://www.cisa.gov/uscert/ics)
- [NCSC: OT security guidance](https://www.ncsc.gov.uk/collection/operational-technology)
