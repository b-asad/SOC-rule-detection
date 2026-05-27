# GEN-LM-002 — Lateral Movement: RDP to New Internal Host

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-LM-002` |
| **MITRE Technique** | T1021.001 — Remote Desktop Protocol |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Identity |
| **Log Source** | `DeviceLogonEvents` (MDE) · `IdentityLogonEvents` (MDI) · Windows Event 4624 |

## Description
RDP authentication from a user or device to an internal host that has not been accessed via RDP in the past 30 days. Attackers use RDP extensively for lateral movement after initial compromise. Workstation-to-workstation RDP is almost never legitimate in well-managed environments.

## Microsoft Sentinel KQL
```kql
// GEN-LM-002 | Frequency: 15m | Lookback: 15m
let BaselineRDP = (
    DeviceLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where LogonType == "RemoteInteractive"
    | distinct AccountName, DeviceName, RemoteDeviceName
);
DeviceLogonEvents
| where TimeGenerated >= ago(15m)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| join kind=leftanti BaselineRDP on AccountName, DeviceName, RemoteDeviceName
| project TimeGenerated, AccountName, DeviceName, RemoteDeviceName, LogonType
| extend AlertTitle = strcat("New RDP: ", AccountName, " from ", DeviceName, " to ", RemoteDeviceName)
| extend Note = "Workstation-to-workstation RDP is almost always malicious"
```

## Defender for Identity
MDI detects: **Remote code execution attempt** and anomalous RDP lateral movement.

## Defender XDR — Advanced Hunting
```kql
// GEN-LM-002 | Run: Every hour
let Baseline = (
    IdentityLogonEvents | where Timestamp between (ago(30d)..ago(1d))
    | where Protocol == "Rdp" and ActionType == "LogonSuccess"
    | distinct AccountName, DeviceName, DestinationDeviceName
);
IdentityLogonEvents
| where Timestamp >= ago(1h) and Protocol == "Rdp" and ActionType == "LogonSuccess"
| join kind=leftanti Baseline on AccountName, DeviceName, DestinationDeviceName
| project Timestamp, AccountName, DeviceName, DestinationDeviceName
```

## Investigation Guide
**Step 1:** Is source-to-destination pair genuinely new or recently renamed device? Check asset register.
**Step 2:** Is this workstation-to-workstation? If yes: high confidence malicious.
**Step 3:** What did the attacker do on the destination host?
```kql
DeviceProcessEvents | where DeviceName == "<DEST_DEVICE>" | where Timestamp >= "<RDP_TIME>"
| where AccountName == "<ACCOUNT>"
| project Timestamp, FileName, ProcessCommandLine | order by Timestamp asc
```

## Response Actions
- [ ] Isolate both source and destination devices
- [ ] Reset the abused account's password
- [ ] Search for further RDP hops from the destination device

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| IT admin RDP to a new server | Add approved admin-to-server pairs to exclusion watchlist |
| New device onboarded (baseline gap) | Verify device age < 30 days; add to allowlist |

## References - [MITRE T1021.001](https://attack.mitre.org/techniques/T1021/001/)
