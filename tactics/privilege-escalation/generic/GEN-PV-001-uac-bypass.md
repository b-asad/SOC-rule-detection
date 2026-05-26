# GEN-PV-001 — Privilege Escalation: UAC Bypass via Registry

| Field | Value |
|-------|-------|
| Rule ID | GEN-PV-001 |
| Tactic | Privilege Escalation |
| Technique | T1548.002 — Abuse Elevation Control: Bypass UAC |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceRegistryEvents` (MDE) |

## Description
Known UAC bypass technique using registry key modification (Eventvwr, fodhelper, sdclt, ComputerDefaults). A non-elevated process writes to a shell/open command registry path to trick an auto-elevated COM object into executing arbitrary code at high integrity.

---

## Microsoft Sentinel KQL
```kql
// GEN-PV-001 | Frequency: 5m | Lookback: 5m
DeviceRegistryEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "ms-settings\\shell\\open\\command",
    "mscfile\\shell\\open\\command",
    "Classes\\Folder\\shell\\open\\command",
    "Software\\Classes\\exefile\\shell\\runas\\command\\IsolatedCommand"
)
| project TimeGenerated, DeviceName, AccountName, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-PV-001 | Run: Every hour
DeviceRegistryEvents
| where Timestamp >= ago(1h) and ActionType == "RegistryValueSet"
| where RegistryKey has_any ("ms-settings\\shell\\open\\command","mscfile\\shell\\open\\command","Classes\\Folder\\shell\\open\\command")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessSHA256
```

---

## Investigation Guide

**Step 1:** What value was written? Does it point to a malicious binary or command?  
**Step 2:** Was the elevated process subsequently executed?  
```kql
DeviceProcessEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(30m)
| where ProcessIntegrityLevel == "High" or ProcessIntegrityLevel == "System"
| where InitiatingProcessIntegrityLevel != "High"
| project Timestamp, FileName, ProcessCommandLine, ProcessIntegrityLevel, InitiatingProcessFileName
```
**Step 3:** What did the elevated process do? Network connections, file writes, registry changes?

---

## Response Actions
- [ ] Revert the registry key to default value
- [ ] Kill any elevated processes spawned via the bypass
- [ ] Run GEN-CA-001 (LSASS) check — elevation often precedes credential dumping

## References
- [MITRE T1548.002](https://attack.mitre.org/techniques/T1548/002/)
