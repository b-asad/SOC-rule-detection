# SEC-HC-LM-001 — Healthcare: RDP Lateral Movement on Clinical Network

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-HC-LM-001` |
| **MITRE Technique** | T1021.001 — Remote Desktop Protocol |
| **Sector** | Healthcare |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceLogonEvents` (MDE) |
| **Sector Context** | Clinical network workstations, EPR servers, PACS servers, pharmacy hosts |

## Description
RDP lateral movement within the clinical network segment — extremely high risk in healthcare as it can spread ransomware to EPR, pharmacy, and PACS systems, directly impacting patient care. Any new host-to-host RDP connection involving a clinical host should be treated as Critical.

## Microsoft Sentinel KQL
```kql
// SEC-HC-LM-001 | Frequency: 5m | Lookback: 5m
let ClinicalHosts = (_GetWatchlist('ClinicalHosts') | project SearchKey);
DeviceLogonEvents
| where TimeGenerated >= ago(5m)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where DeviceName in~ (ClinicalHosts) or RemoteDeviceName in~ (ClinicalHosts)
    or DeviceName has_any ("epr","pacs","pharmacy","ward","clinical")
    or RemoteDeviceName has_any ("epr","pacs","pharmacy","ward","clinical")
| project TimeGenerated, AccountName, DeviceName, RemoteDeviceName, LogonType
| extend AlertTitle = strcat("RDP to Clinical Host: ", AccountName, " to ", RemoteDeviceName)
| extend PatientSafetyNote = "Clinical system lateral movement — treat as active ransomware precursor"
```

## Investigation Guide
**Step 1 (Immediate):** Isolate both source and destination hosts.
**Step 2:** Has this reached an EPR, pharmacy, or PACS server? If yes: escalate to P1 outbreak protocol.
**Step 3:** Notify CCIO and activate clinical downtime procedures if EPR/pharmacy affected.

## Response Actions
- [ ] Isolate source and destination devices
- [ ] If clinical system reached: activate downtime procedures, notify CCIO
- [ ] Reset abused account password

## References - [MITRE T1021.001](https://attack.mitre.org/techniques/T1021/001/)
