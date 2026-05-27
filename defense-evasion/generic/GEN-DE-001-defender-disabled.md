# GEN-DE-001 — Defense Evasion: Windows Defender / MDE Sensor Disabled

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DE-001` |
| **MITRE Tactic** | Defense Evasion |
| **MITRE Technique** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Sector** | **Generic** — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceRegistryEvents` · `DeviceProcessEvents` (MDE) · Windows Event 5001 |
| **Created** | May 2026 |

---

## Description

Detects disabling of Windows Defender real-time protection, AMSI, or the MDE sensor via registry modification or PowerShell `Set-MpPreference` commands. Attackers disable security tools immediately before deploying malware to avoid detection. This alert often fires in the 60–120 seconds before a ransomware payload is executed.

MDE's **Tamper Protection** feature prevents many of these registry modifications. If this alert fires, it means either Tamper Protection is not enabled or an attacker has found a bypass. **Zero tolerance — never suppress.**

---

## Microsoft Sentinel KQL

```kql
// GEN-DE-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
// POLICY: Never suppress. Zero tolerance.
let DefenderRegistryMods = (
    DeviceRegistryEvents
    | where TimeGenerated >= ago(5m)
    | where RegistryKey has_any (
        "Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
        "Windows Defender\\DisableAntiSpyware",
        "Windows Defender\\DisableAntiVirus",
        "Windows Defender\\Features\\TamperProtection",
        "Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring",
        "Windows Defender\\Real-Time Protection\\DisableIOAVProtection",
        "Windows Defender\\Real-Time Protection\\DisableScriptScanning",
        "SENSE\\Start"  // MDE sensor service start type
    )
    | where (RegistryValueData == "1" or RegistryValueData == "4")  // 1 = Disable, 4 = Disabled service
    | project TimeGenerated, DeviceName, AccountName,
        RegistryKey, RegistryValueName, RegistryValueData,
        InitiatingProcessFileName, InitiatingProcessSHA256
);
let DefenderPSMods = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has "Set-MpPreference"
    | where ProcessCommandLine has_any (
        "DisableRealtimeMonitoring","DisableIOAVProtection",
        "DisableBehaviorMonitoring","DisableAntiSpyware",
        "ExclusionPath","ExclusionExtension","ExclusionProcess"
    )
    | project TimeGenerated, DeviceName, AccountName,
        ProcessCommandLine, InitiatingProcessFileName, SHA256
);
DefenderRegistryMods | union DefenderPSMods
| extend AlertTitle = strcat("Defender/MDE Disabled on ", DeviceName)
| extend Severity = "Critical"
| extend ImmediateAction = "Investigate immediately. Re-enable Defender. Consider device isolation."
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-DE-001 | Run: Every hour | Severity: High | Category: DefenseEvasion
let RegistryMods = (
    DeviceRegistryEvents
    | where Timestamp >= ago(1h)
    | where RegistryKey has_any (
        "Windows Defender\\Real-Time Protection",
        "Windows Defender\\DisableAntiSpyware",
        "Windows Defender\\Features\\TamperProtection"
    )
    | where RegistryValueData in ("1","4")
    | project Timestamp, DeviceName, AccountName,
        RegistryKey, RegistryValueData, InitiatingProcessFileName
);
let PSMods = (
    DeviceProcessEvents
    | where Timestamp >= ago(1h)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has "Set-MpPreference"
    | where ProcessCommandLine has_any ("DisableRealtimeMonitoring","DisableIOAVProtection")
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
);
RegistryMods | union PSMods | order by Timestamp desc
```

---

## Defender for Endpoint — Configuration Checks

**Verify Tamper Protection status:**
MDE portal → Settings → Endpoints → Advanced features → **Tamper protection: ON**

**Check Defender status on the device:**
```kql
DeviceInfo
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp >= ago(1h)
| project Timestamp, DeviceName, AvMode, AvSignatureVersion, AvEngineVersion, AvIsSignatureUpToDate, OnboardingStatus
```

**What ran while Defender was disabled:**
```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (<DISABLE_TIME> .. <REENABLE_TIME>)
| where InitiatingProcessFileName !in~ ("svchost.exe","services.exe","wininit.exe")
| project Timestamp, FileName, ProcessCommandLine, SHA256, FolderPath, AccountName
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Re-enable Defender immediately (< 5 min)**
MDE portal → Device → Security settings → Force Defender update and scan.
Also confirm MDE sensor is reporting: check `OnboardingStatus` in `DeviceInfo`.

**Step 2 — What disabled it? (5–15 min)**
Who ran the command? What was the parent process?
- If PowerShell ran `Set-MpPreference`: trace back to what ran the PowerShell (GEN-EX-001 pattern)
- If a registry modification by an unsigned process: the process is the malware dropper

**Step 3 — Identify what ran during the blind window (15–30 min)**
Run the "what ran while disabled" query above. Submit all unknown hashes to VirusTotal. Any unknown or malicious binary = confirmed compromise.

---

## Response Actions
**Immediate**
- [ ] Re-enable Defender real-time protection via MDE portal
- [ ] If malicious binary detected during the blind window: isolate the device
- [ ] Ensure Tamper Protection is enabled to prevent recurrence

**Short-term**
- [ ] Enable Tamper Protection on ALL customer endpoints via MDE policy
- [ ] Review all processes run during the Defender-disabled window
- [ ] Submit unknown hashes to Microsoft Defender Threat Intelligence

## False Positives — None expected in production. Zero tolerance.

## References
- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [MDE: Tamper protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
