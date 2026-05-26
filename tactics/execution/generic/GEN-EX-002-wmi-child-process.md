# GEN-EX-002 — Execution via WMI: WmiPrvSE Spawns Shell

| Field | Value |
|-------|-------|
| Rule ID | GEN-EX-002 |
| Tactic | Execution |
| Technique | T1047 — Windows Management Instrumentation |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceProcessEvents` (MDE), Sysmon Event ID 1 |

## Description
`WmiPrvSE.exe` (WMI Provider Host) spawns `cmd.exe` or `powershell.exe`, indicating WMI is being used to execute commands — commonly used for lateral movement, persistence via WMI subscriptions, and living-off-the-land execution.

---

## Microsoft Sentinel KQL
```kql
// GEN-EX-002 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-EX-002 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

---

## Investigation Guide

**Step 1:** What command was executed? Decode if PowerShell.  
**Step 2:** Is this local execution or remote (WMI over network from another host)?  
**Step 3 — Check remote origin:**
```kql
DeviceNetworkEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(1h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe" and RemotePort == 135
| project Timestamp, RemoteIP, RemotePort
```
If remote IP found: that host is the attacker's pivot point. Investigate and isolate both.

---

## Response Actions
- [ ] Kill the WMI-spawned process
- [ ] If remote WMI: isolate origin host
- [ ] Check for WMI event subscriptions (persistence)
- [ ] Review for lateral movement from this host

## References
- [MITRE T1047](https://attack.mitre.org/techniques/T1047/)
