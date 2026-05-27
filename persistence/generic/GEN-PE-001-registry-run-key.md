# GEN-PE-001 — Persistence: Registry Run Key Created by Suspicious Process

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-PE-001` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Sector** | **Generic** — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceRegistryEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Detects creation of a new registry run key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, or equivalent autostart locations by a process that is not a known and approved installer. Registry run keys cause a program to execute automatically at user logon or system startup — one of the most common persistence mechanisms across all malware families.

---

## Microsoft Sentinel KQL

```kql
// GEN-PE-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
let ApprovedInstallers = (_GetWatchlist('ApprovedInstallers') | project SearchKey);
DeviceRegistryEvents
| where TimeGenerated >= ago(5m)
| where RegistryKey has_any (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "CurrentVersion\\RunServices",
    "CurrentVersion\\RunServicesOnce",
    "Winlogon\\Userinit",
    "Winlogon\\Shell",
    "CurrentVersion\\Windows\\Load",
    "CurrentVersion\\Windows\\Run"
)
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| where not(InitiatingProcessSHA256 in (ApprovedInstallers))
| where InitiatingProcessFileName !in~ (
    "msiexec.exe","setup.exe","install.exe","Update.exe",
    "MicrosoftEdgeUpdate.exe","GoogleUpdate.exe","OneDriveSetup.exe",
    "Teams.exe","DropboxUpdate.exe","AdobeARM.exe"
)
| project
    TimeGenerated, DeviceName, AccountName,
    RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessFolderPath, InitiatingProcessSHA256
| extend AlertTitle = strcat("New Registry Run Key by ", InitiatingProcessFileName)
| extend Severity = "High"
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-PE-001 | Run: Every hour | Severity: Medium | Category: Persistence
DeviceRegistryEvents
| where Timestamp >= ago(1h)
| where RegistryKey has_any ("CurrentVersion\\Run","CurrentVersion\\RunOnce","Winlogon\\Userinit")
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| where InitiatingProcessFileName !in~ (
    "msiexec.exe","setup.exe","install.exe","Update.exe",
    "MicrosoftEdgeUpdate.exe","GoogleUpdate.exe","OneDriveSetup.exe"
)
| project
    Timestamp, DeviceName, AccountName,
    RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessSHA256
| order by Timestamp desc
```

---

## Defender for Endpoint — Registry Investigation

```kql
// Full registry persistence review for a specific device
DeviceRegistryEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(24h) .. now())
| where RegistryKey has_any ("Run","RunOnce","Winlogon","Services","Scheduled")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, ActionType
| order by Timestamp desc
```

MDE Live Response — query registry directly:
```
# Check HKCU run keys
run_script query_registry HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Check HKLM run keys
run_script query_registry HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

---

## Investigation Guide

**Step 1 — What does the run key point to? (< 5 min)**
The `RegistryValueData` field contains the path to the binary or command that will execute at logon.
- Is the path in a temp folder, `%APPDATA%`, `%PROGRAMDATA%`, or `C:\Users`? → Almost certainly malicious
- Is the binary signed? Submit the hash to VirusTotal
- Does the path contain a strange name (random characters, looks like a legitimate system file)?

**Step 2 — What process created the key? (5–15 min)**
Correlate `InitiatingProcessFileName` and `InitiatingProcessSHA256` with other alerts on this device. Did GEN-EX-001 (PowerShell) or GEN-IA-001 (Office macro) fire on the same device recently?

**Step 3 — Remove and scan**
Delete the run key via MDE Live Response. Run a full antivirus scan. Check for other persistence mechanisms.

---

## Response Actions
- [ ] Delete the malicious run key via MDE Live Response
- [ ] Quarantine or delete the pointed binary (SHA256 block in MDE custom indicators)
- [ ] Run full AV scan on the device
- [ ] Check for additional persistence: scheduled tasks, services, WMI subscriptions
- [ ] Trace the initiating process back to determine how the malware was initially delivered

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Software installer creating a legitimate startup entry | Add the signed installer's SHA256 to the `ApprovedInstallers` watchlist |
| Browser or application auto-updater | Add specific installer executables to the exclusion list in the query — verify they are from known vendor paths |

## References
- [MITRE T1547.001](https://attack.mitre.org/techniques/T1547/001/)
