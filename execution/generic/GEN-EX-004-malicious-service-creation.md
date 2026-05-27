# GEN-EX-004 — Execution/Persistence: Malicious Windows Service Created

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EX-004` |
| **MITRE Tactic** | Execution / Persistence |
| **MITRE Technique** | T1569.002 / T1543.003 — Service Execution / Create or Modify System Service |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | Windows Security Event 4697 · `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

A new Windows service created by a non-standard process, pointing to an executable in a suspicious path. Services run as SYSTEM by default, making this both a privilege escalation and persistence technique. Used by PsExec-based lateral movement, Cobalt Strike, and ransomware for execution. Windows Event 4697 captures service creation; MDE captures `sc.exe` usage.

---

## Microsoft Sentinel KQL

```kql
// GEN-EX-004 | Frequency: 5m | Lookback: 5m
// Detection A: Windows Event 4697 — service installed
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID == 4697
| extend ServiceName    = tostring(EventData.ServiceName)
| extend ServiceFileName = tostring(EventData.ServiceFileName)
| extend AccountName    = tostring(EventData.SubjectUserName)
| where ServiceFileName has_any (
    "Temp","AppData","ProgramData","Users\\Public","\\Downloads\\",
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe"
)
| project TimeGenerated, Computer, AccountName, ServiceName, ServiceFileName
| extend AlertTitle = strcat("Suspicious Service Installed: ", ServiceName)
```

```kql
// Detection B: sc.exe or service manager spawned by unusual parent
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where FileName =~ "sc.exe" and ProcessCommandLine has_any ("create","binpath","start")
| where InitiatingProcessFileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"
)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-EX-004 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any ("create","binpath")
| where InitiatingProcessFileName !in~ ("services.exe","svchost.exe","msiexec.exe","setup.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

---

## Investigation Guide

**Step 1 — What is the service binary path? (0–10 min)**
Is the binary in a standard system path (`System32`, `Program Files`) or a user-writable location (`Temp`, `AppData`, `ProgramData`)?
Non-standard path = almost certainly malicious. Submit hash to VirusTotal.

**Step 2 — Is this PsExec lateral movement?**
```kql
DeviceProcessEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(30m)
| where FileName =~ "psexesvc.exe" or ProcessCommandLine has "psexec"
| project Timestamp, FileName, ProcessCommandLine, AccountName
```
If PsExec service found: another host in the environment created this service. Find the origin.

---

## Response Actions
- [ ] Stop and delete the malicious service: `sc stop <name>` then `sc delete <name>`
- [ ] Delete or quarantine the service binary
- [ ] If PsExec: investigate the origin host — it is the attacker's current position
- [ ] Check for additional services created in the same time window

## References - [MITRE T1569.002](https://attack.mitre.org/techniques/T1569/002/) | [MITRE T1543.003](https://attack.mitre.org/techniques/T1543/003/)
