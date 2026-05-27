# GEN-DE-004 — Defense Evasion: Process Masquerading

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DE-004` |
| **MITRE Tactic** | Defense Evasion |
| **MITRE Technique** | T1036.005 — Masquerading: Match Legitimate Name or Location |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

A process runs with the same name as a legitimate Windows system binary but from the wrong directory (e.g., `svchost.exe` running from `C:\Users\Public\` instead of `C:\Windows\System32\`). Attackers name their malware to blend in with system processes. High-fidelity detection — legitimate system processes almost never run from user-writable locations.

---

## Microsoft Sentinel KQL

```kql
// GEN-DE-004 | Frequency: 5m | Lookback: 5m
let LegitPaths = dynamic([
    "c:\\windows\\system32\\","c:\\windows\\syswow64\\",
    "c:\\windows\\","c:\\program files\\","c:\\program files (x86)\\"
]);
let SystemBinaries = dynamic([
    "svchost.exe","lsass.exe","services.exe","csrss.exe","winlogon.exe",
    "wininit.exe","explorer.exe","taskhostw.exe","taskhost.exe","spoolsv.exe",
    "dllhost.exe","mmc.exe","searchindexer.exe","lsm.exe","smss.exe","conhost.exe"
]);
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where FileName in~ (SystemBinaries)
| where not(FolderPath has_any (LegitPaths))
| where FolderPath != ""
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
    ProcessCommandLine, SHA256, InitiatingProcessFileName
| extend AlertTitle = strcat("Masquerading: ", FileName, " running from ", FolderPath)
| extend Note = "Legitimate system binaries never run from user-writable paths"
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-DE-004 | Run: Every hour
let SystemBinaries = dynamic(["svchost.exe","lsass.exe","services.exe","csrss.exe","winlogon.exe","explorer.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where FileName in~ (SystemBinaries)
| where not(FolderPath startswith @"c:\windows\")
    and not(FolderPath startswith @"c:\program files")
| where FolderPath != ""
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1:** Is the binary unsigned? Run: `Get-AuthenticodeSignature <path>` via Live Response.
**Step 2:** Submit SHA256 to VirusTotal — masquerading binaries are almost always malicious.
**Step 3:** What launched this binary? Trace parent process chain.

---

## Response Actions
- [ ] Kill the masquerading process via MDE Live Response
- [ ] Delete the malicious binary
- [ ] Block SHA256 in MDE custom indicators

## References - [MITRE T1036.005](https://attack.mitre.org/techniques/T1036/005/)
