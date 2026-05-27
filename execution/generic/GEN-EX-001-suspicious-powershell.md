# GEN-EX-001 — Execution: Suspicious PowerShell with Encoded Command or Download Cradle

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EX-001` |
| **MITRE Tactic** | Execution |
| **MITRE Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Sector** | **Generic** — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) · `DeviceEvents` (MDE — Script Block Logging) |
| **Created** | May 2026 |

---

## Description

Detects PowerShell launched with flags commonly used by attackers: encoded commands (`-EncodedCommand`, `-enc`), download cradles (`IEX`, `DownloadString`, `WebClient`), execution policy bypass (`-ExecutionPolicy Bypass`), or hidden window mode (`-WindowStyle Hidden`). PowerShell abuse is present in over 80% of malware campaigns as a flexible LOLBin for downloading payloads, establishing persistence, and executing shellcode.

MDE captures **PowerShell Script Block Logging** content in `DeviceEvents` under ActionType `PowerShellCommand` — use this for deeper inspection of obfuscated commands after the initial alert fires.

---

## Microsoft Sentinel KQL

```kql
// GEN-EX-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
let KnownGoodParents = dynamic([
    "devenv.exe","msbuild.exe","AzurePowerShell.exe",
    "AzureAD.exe","az.cmd","AzureConnectedMachineAgent.exe"
]);
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "-EncodedCommand","-enc ","-e ",
    "IEX","Invoke-Expression",
    "DownloadString","DownloadFile","DownloadData",
    "Net.WebClient","System.Net.WebClient",
    "-ExecutionPolicy Bypass","-ep bypass","-ep b",
    "WindowStyle Hidden","-w hidden","-WindowStyle H",
    "FromBase64String","[Convert]::",
    "Invoke-WebRequest","iwr ","curl ","wget ",
    "Start-BitsTransfer","Invoke-RestMethod",
    "New-Object System.Net.Sockets",
    "TCPClient","System.Net.Sockets"
)
| where not(InitiatingProcessFileName in~ (KnownGoodParents))
| project
    TimeGenerated, DeviceName, AccountName, AccountDomain,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, SHA256, FolderPath
| extend Severity = "High"
| extend MitreTechnique = "T1059.001"
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-EX-001 | Run: Every hour | Severity: High | Category: Execution
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "-EncodedCommand","-enc ","IEX","Invoke-Expression",
    "DownloadString","Net.WebClient","WebClient",
    "-ExecutionPolicy Bypass","FromBase64String",
    "WindowStyle Hidden","-w hidden",
    "New-Object System.Net.Sockets","TCPClient"
)
| project
    Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

---

## Defender for Endpoint — Script Block Logging

```kql
// Retrieve actual script content (even if obfuscated at process level)
DeviceEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(2h) .. now())
| where ActionType == "PowerShellCommand"
| project Timestamp, AdditionalFields, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc
// AdditionalFields contains the script block content
```

---

## Investigation Guide

**Step 1 — Decode the command (< 10 min)**

For `-EncodedCommand` payloads:
```powershell
# Run on analyst workstation — NOT on customer device
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("PASTE_BASE64_HERE")
)
```

Use CyberChef: From Base64 → Decode Text (UTF-16LE for PowerShell).

**Step 2 — Identify download target**
If a URL is present, submit immediately to VirusTotal. Block the domain at firewall and in MDE custom indicators.

**Step 3 — Child processes and network connections**
```kql
DeviceProcessEvents | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(30m)
| project Timestamp, FileName, ProcessCommandLine | order by Timestamp asc
```

**Step 4 — Persistence check**
```kql
DeviceRegistryEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(1h)
| where RegistryKey has_any ("CurrentVersion\\Run","Services","Scheduled")
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
```

---

## Response Actions

**Immediate**
- [ ] Kill the PowerShell process via MDE Live Response: `kill <PID>`
- [ ] Block download URL and C2 IP in MDE custom indicators
- [ ] Quarantine any dropped files (SHA256 block)
- [ ] Isolate device if payload downloaded or executed

**Short-term**
- [ ] Enable PowerShell Constrained Language Mode via GPO
- [ ] Enable Script Block Logging via Group Policy (records all PowerShell content)
- [ ] Consider enabling AMSI (Antimalware Scan Interface) enforcement

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Intune / Endpoint Manager deployment scripts | Exclude by signed parent process (`Microsoft.Management.Services.IntuneWindowsAgent.exe`) |
| Azure Arc management commands | Exclude by `AzureConnectedMachineAgent.exe` parent — already in KnownGoodParents |
| IT team automation (Ansible WinRM, Chef) | Exclude by specific management server IP initiating the WinRM session |

## References
- [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft: PowerShell Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
