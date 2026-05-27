# GEN-LM-003 — Lateral Movement: SMB / Windows Admin Shares

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-LM-003` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | T1021.002 — SMB/Windows Admin Shares |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR |
| **Log Source** | `IdentityLogonEvents` (MDI) · `DeviceLogonEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Lateral movement via SMB using `ADMIN$`, `C$`, `IPC$` admin shares — the mechanism used by PsExec, Impacket's smbexec/wmiexec, and many RATs for remote execution. Workstation-to-workstation SMB admin share access is almost never legitimate. Combines with a 30-day baseline to detect new host-to-host pairs.

---

## Microsoft Sentinel KQL

```kql
// GEN-LM-003 | Frequency: 15m | Lookback: 15m
let BaselineSMB = (
    IdentityLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where Protocol == "Smb" and ActionType == "LogonSuccess"
    | where LogonType in ("Network","NetworkCleartext")
    | distinct AccountName, DeviceName, DestinationDeviceName
);
IdentityLogonEvents
| where TimeGenerated >= ago(15m)
| where Protocol == "Smb" and ActionType == "LogonSuccess"
| where LogonType in ("Network","NetworkCleartext")
| where not(AccountName endswith "$")  // Exclude machine accounts
| join kind=leftanti BaselineSMB on AccountName, DeviceName, DestinationDeviceName
| project TimeGenerated, AccountName, DeviceName, DestinationDeviceName, Protocol, LogonType
| extend AlertTitle = strcat("New SMB Lateral Movement: ", DeviceName, " → ", DestinationDeviceName)
| extend Note = "Workstation-to-workstation SMB is almost never legitimate"
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-LM-003 | Run: Every hour
let Baseline = (IdentityLogonEvents | where Timestamp between (ago(30d)..ago(1d))
    | where Protocol == "Smb" | distinct AccountName, DeviceName, DestinationDeviceName);
IdentityLogonEvents
| where Timestamp >= ago(1h) and Protocol == "Smb" and ActionType == "LogonSuccess"
| where not(AccountName endswith "$")
| join kind=leftanti Baseline on AccountName, DeviceName, DestinationDeviceName
| project Timestamp, AccountName, DeviceName, DestinationDeviceName
```

---

## Investigation Guide

**Step 1:** Is source a workstation? Workstation-to-workstation SMB = high confidence malicious.
**Step 2:** Was PsExec used? Check for PSEXESVC service on the destination.
**Step 3:** What was executed on the destination via SMB?
```kql
DeviceProcessEvents | where DeviceName == "<DEST>" | where Timestamp >= "<SMB_TIME>"
| where AccountName == "<ACCOUNT>" | project Timestamp, FileName, ProcessCommandLine
```

---

## Response Actions
- [ ] Isolate both source and destination devices
- [ ] Check for PSEXESVC service on destination and remove
- [ ] Block SMB (port 445) workstation-to-workstation at firewall

## References - [MITRE T1021.002](https://attack.mitre.org/techniques/T1021/002/)
