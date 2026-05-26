# GEN-DE-001 — Defense Evasion: Windows Defender / AV Disabled

| Field | Value |
|-------|-------|
| Rule ID | GEN-DE-001 |
| Tactic | Defense Evasion |
| Technique | T1562.001 — Impair Defenses: Disable or Modify Tools |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceRegistryEvents`, `DeviceProcessEvents` (MDE), Windows Event 5001 |

## Description
Windows Defender real-time protection disabled via registry modification or `Set-MpPreference` PowerShell command. Attackers disable AV immediately before deploying malware to prevent detection. **Zero tolerance — never suppress.**

---

## Microsoft Sentinel KQL
```kql
// GEN-DE-001 | Frequency: 5m | Lookback: 5m
let DefenderDisabled = (
    DeviceRegistryEvents
    | where TimeGenerated >= ago(5m)
    | where RegistryKey has_any ("Windows Defender","Windows Defender\\Real-Time Protection","Windows Defender\\Features")
    | where RegistryValueName in ("DisableAntiSpyware","DisableAntiVirus","DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableIOAVProtection")
    | where RegistryValueData == "1"
    | project TimeGenerated, DeviceName, AccountName, RegistryKey, RegistryValueName, InitiatingProcessFileName, InitiatingProcessCommandLine
);
let MPPreference = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where FileName =~ "powershell.exe" and ProcessCommandLine has "Set-MpPreference"
    | where ProcessCommandLine has_any ("DisableRealtimeMonitoring","DisableIOAVProtection","DisableBehaviorMonitoring","DisableAntiSpyware")
    | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
);
DefenderDisabled | union MPPreference
```
**Sentinel Settings:** Frequency `5m` · Threshold `> 0` · Playbook: `PB-ISOLATE-HOST`

---

## Defender XDR — Advanced Hunting
```kql
// GEN-DE-001 | Run: Every hour
DeviceRegistryEvents
| where Timestamp >= ago(1h)
| where RegistryKey has "Windows Defender"
| where RegistryValueName in ("DisableAntiSpyware","DisableRealtimeMonitoring","DisableBehaviorMonitoring")
| where RegistryValueData == "1"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, InitiatingProcessFileName
```

---

## Defender for Endpoint — Tamper Protection
Ensure **Tamper Protection** is enabled on all endpoints in MDE Security Settings.  
Tamper Protection prevents the registry keys above from being modified by non-privileged processes — this rule serves as a secondary alert if tamper protection is bypassed.

MDE natively alerts: **Tampering with Windows Defender detected** — ensure this alert is P1.

---

## Investigation Guide

**Step 1 — Re-enable Defender (< 5 min)**  
Via MDE → Device → Run antivirus scan / Security settings → Ensure Defender active.

**Step 2 — What Disabled It**  
What process modified the registry key? Is it a known malware tool or living-off-the-land?

**Step 3 — What Ran While AV Was Disabled**
```kql
DeviceProcessEvents | where DeviceName == "<DEVICE>" | where Timestamp between (<DISABLE_TIME> .. now())
| where InitiatingProcessFileName !in~ ("svchost.exe","services.exe","wininit.exe")
| project Timestamp, FileName, ProcessCommandLine, SHA256, FolderPath | order by Timestamp asc
```

---

## Response Actions
- [ ] Re-enable Defender / confirm MDE sensor active
- [ ] Isolate device if malicious process detected during AV-disabled window
- [ ] Submit all hashes of processes run during disabled window to VirusTotal
- [ ] Enable Tamper Protection to prevent recurrence

## False Positives — None expected. Alert all instances.

## References
- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
