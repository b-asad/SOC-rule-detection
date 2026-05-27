# GEN-EX-002 — Execution: WMI Spawns Shell Process

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EX-002` |
| **MITRE Technique** | T1047 — Windows Management Instrumentation |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |

## Description
`WmiPrvSE.exe` (WMI Provider Host) spawns `cmd.exe` or `powershell.exe`. WMI is commonly abused for remote execution, persistence (WMI event subscriptions), and lateral movement as it leaves fewer traces than traditional remote services. Both local and remote WMI execution produce this parent-child pattern.

## Microsoft Sentinel KQL
```kql
// GEN-EX-002 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe")
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| extend AlertTitle = strcat("WMI spawned ", FileName, " on ", DeviceName)
```

## Defender XDR — Advanced Hunting
```kql
// GEN-EX-002 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

## Defender for Endpoint
```kql
// Is this remote WMI (lateral movement) or local?
DeviceNetworkEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(1h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where RemotePort == 135
| project Timestamp, RemoteIP, RemotePort
// If RemoteIP found → origin host is the attacker's pivot point. Isolate both.
```

## Investigation Guide
**Step 1:** Decode the command if PowerShell (see GEN-EX-001).
**Step 2:** Is this local or remote WMI? Run network query above — remote origin = two-host investigation.
**Step 3:** Check for WMI event subscription persistence:
```kql
DeviceEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where ActionType == "WmiBindEventFilter"
| project Timestamp, InitiatingProcessFileName, AdditionalFields
```

## Response Actions
- [ ] Kill the WMI-spawned process via MDE Live Response
- [ ] If remote WMI: isolate origin host and investigate lateral movement
- [ ] Check and remove any WMI event subscriptions (persistence)

## References - [MITRE T1047](https://attack.mitre.org/techniques/T1047/)
