# GEN-PV-001 — Privilege Escalation: UAC Bypass via Registry Shell Command

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-PV-001` |
| **MITRE Tactic** | Privilege Escalation |
| **MITRE Technique** | T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC |
| **Sector** | **Generic** — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceRegistryEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Detects known UAC bypass techniques that modify registry shell command keys to hijack auto-elevated COM objects (`eventvwr.exe`, `fodhelper.exe`, `sdclt.exe`, `ComputerDefaults.exe`). A non-elevated process writes a malicious command to a shell/open registry path, then triggers the auto-elevated binary to execute it at high integrity — achieving privilege escalation without a UAC prompt.

These registry keys are almost never legitimately modified by user-space processes. This is a very high fidelity rule with an extremely low false positive rate.

---

## Microsoft Sentinel KQL

```kql
// GEN-PV-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
DeviceRegistryEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "ms-settings\\shell\\open\\command",          // fodhelper, ComputerDefaults bypass
    "mscfile\\shell\\open\\command",               // eventvwr bypass
    "Classes\\Folder\\shell\\open\\command",        // sdclt bypass
    "Classes\\exefile\\shell\\runas\\command\\IsolatedCommand",  // fileless bypass
    "Classes\\.hta\\shell\\open\\command",          // HTA hijack
    "Classes\\ms-settings\\shell\\open\\command"   // settings bypass variant
)
| project
    TimeGenerated, DeviceName, AccountName, AccountDomain,
    RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessIntegrityLevel, InitiatingProcessSHA256
| extend AlertTitle = strcat("UAC Bypass Registry Modification by ", InitiatingProcessFileName)
| extend Severity = "High"
| extend Note = "This key is almost never legitimately modified. Treat as high-confidence malicious."
```

**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0`
> Note: This rule has an extremely low FP rate. Consider enabling auto-isolation after 7-day validation.

---

## Defender XDR — Advanced Hunting

```kql
// GEN-PV-001 | Run: Every hour | Severity: High | Category: PrivilegeEscalation
DeviceRegistryEvents
| where Timestamp >= ago(1h)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "ms-settings\\shell\\open\\command",
    "mscfile\\shell\\open\\command",
    "Classes\\Folder\\shell\\open\\command",
    "Classes\\exefile\\shell\\runas\\command\\IsolatedCommand",
    "Classes\\ms-settings\\shell\\open\\command"
)
| project
    Timestamp, DeviceName, AccountName,
    RegistryKey, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessIntegrityLevel, InitiatingProcessSHA256
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1 — What command was injected? (< 5 min)**
The `RegistryValueData` field contains the malicious command. What does it execute?
- PowerShell with encoded command → decode immediately (see GEN-EX-001)
- A binary in a temp path → submit to VirusTotal
- A reverse shell one-liner → treat as active C2

**Step 2 — Was the elevated process triggered? (5–15 min)**
```kql
// Did the auto-elevated binary execute after the registry modification?
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (<REGISTRY_WRITE_TIME> .. now())
| where FileName in~ ("fodhelper.exe","eventvwr.exe","sdclt.exe","ComputerDefaults.exe")
| project Timestamp, FileName, ProcessCommandLine, ProcessIntegrityLevel, AccountName
```

**Step 3 — Post-elevation activity (15–30 min)**
What did the process do at High integrity? Credential dumping (GEN-CA-001)? Service creation (persistence)? Network connection (C2)?

---

## Response Actions
- [ ] Revert the malicious registry key to its default state (or delete)
- [ ] Kill any elevated process spawned via the bypass
- [ ] If High integrity process ran: assume privilege escalation succeeded — check for LSASS access, persistence, and C2

## False Positives — Virtually none. These registry keys are not legitimately modified by user-space processes.

## References
- [MITRE T1548.002](https://attack.mitre.org/techniques/T1548/002/)
- [UACME: UAC bypass methods catalogue](https://github.com/hfiref0x/UACME)
