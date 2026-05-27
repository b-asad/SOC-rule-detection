# GEN-EX-003 — Execution/Persistence: Scheduled Task Created by Suspicious Process

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EX-003` |
| **MITRE Tactic** | Execution / Persistence |
| **MITRE Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) · Windows Security Event 4698 |
| **Created** | May 2026 |

---

## Description

Scheduled task created by a non-standard process — a reliable persistence mechanism and execution technique used across ransomware, RATs, and APT implants. Unlike registry run keys, scheduled tasks survive reboots, can run as SYSTEM, and can execute at specific times or triggers including at logon, at startup, on event, and periodically. Any scheduled task created by a shell or scripting engine warrants investigation.

---

## Microsoft Sentinel KQL

```kql
// GEN-EX-003 | Frequency: 5m | Lookback: 5m
let ApprovedSchedulers = (_GetWatchlist('ApprovedInstallers') | project SearchKey);
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID == 4698  // Scheduled task created
| extend TaskName    = tostring(EventData.TaskName)
| extend TaskContent = tostring(EventData.TaskContent)
| extend TaskRun     = extract(@"<Command>(.*?)</Command>", 1, TaskContent)
| where TaskRun !in~ (ApprovedSchedulers)
| where TaskRun has_any (
    "powershell","cmd","wscript","cscript","mshta","regsvr32","rundll32",
    "certutil","bitsadmin","msiexec","wmic","curl","wget",
    "AppData","Temp","ProgramData","Users\\Public"
)
| project TimeGenerated, Computer, SubjectUserName, TaskName, TaskRun, TaskContent
| extend AlertTitle = strcat("Suspicious Scheduled Task Created: ", TaskName)
```

```kql
// Also catch schtasks.exe spawned by suspicious parent
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where InitiatingProcessFileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe"
)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-EX-003 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where InitiatingProcessFileName !in~ (
    "msiexec.exe","setup.exe","install.exe","Update.exe",
    "MicrosoftEdgeUpdate.exe","GoogleUpdate.exe"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

---

## Defender for Endpoint

```kql
// Enumerate all scheduled tasks on a device for forensic review
DeviceProcessEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where FileName =~ "schtasks.exe"
| project Timestamp, ProcessCommandLine, AccountName
```
MDE Live Response: `run_script list_scheduled_tasks`

---

## Investigation Guide

**Step 1 — What does the task run? (0–10 min)**
Parse the `TaskRun` or command line field. Is the command:
- A binary in `%TEMP%` or `%APPDATA%`? → Almost certainly malicious
- An encoded PowerShell command? → Decode immediately (see GEN-EX-001)
- A legitimate binary with suspicious arguments?

**Step 2 — Parent process (10–20 min)**
What created the scheduled task? A PowerShell script, a wscript, an Office macro chain?
Correlate with GEN-IA-001 or GEN-EX-001 alerts on the same device around the same time.

**Step 3 — Delete and scan**
Delete the malicious scheduled task. Run full AV scan. Check for other persistence.

---

## Response Actions
- [ ] Delete the malicious scheduled task via MDE Live Response or schtasks /delete
- [ ] Quarantine any binary the task would have executed
- [ ] Trace back to initial delivery — correlate with other alerts on the device
- [ ] Check for additional persistence (registry run keys, services, WMI subscriptions)

## References - [MITRE T1053.005](https://attack.mitre.org/techniques/T1053/005/)
