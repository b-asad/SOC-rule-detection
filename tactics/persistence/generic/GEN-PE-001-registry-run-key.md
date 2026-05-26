# GEN-PE-001 — Persistence: Registry Run Key Modification

| Field | Value |
|-------|-------|
| Rule ID | GEN-PE-001 |
| Tactic | Persistence |
| Technique | T1547.001 — Registry Run Keys / Startup Folder |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceRegistryEvents` (MDE) |

## Description
A new or modified registry run key created under `HKCU` or `HKLM` `CurrentVersion\Run` by a non-standard process. One of the most common persistence mechanisms across all malware families.

---

## Microsoft Sentinel KQL
```kql
// GEN-PE-001 | Frequency: 5m | Lookback: 5m
let ApprovedInstallers = (_GetWatchlist('ApprovedInstallers') | project SearchKey);
DeviceRegistryEvents
| where TimeGenerated >= ago(5m)
| where RegistryKey has_any ("CurrentVersion\\Run","CurrentVersion\\RunOnce","CurrentVersion\\RunServices")
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| where not(InitiatingProcessFileName in~ (ApprovedInstallers))
| where InitiatingProcessFileName !in~ ("msiexec.exe","setup.exe","install.exe","Update.exe")
| project TimeGenerated, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-PE-001 | Run: Every hour
DeviceRegistryEvents
| where Timestamp >= ago(1h)
| where RegistryKey has_any ("CurrentVersion\\Run","CurrentVersion\\RunOnce")
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| where InitiatingProcessFileName !in~ ("msiexec.exe","setup.exe","install.exe","MicrosoftEdgeUpdate.exe","GoogleUpdate.exe","OneDriveSetup.exe")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessSHA256
```

---

## Defender for Endpoint — Registry Investigation
```kql
DeviceRegistryEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where RegistryKey has "Run" | project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```
MDE Live Response: `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

---

## Investigation Guide

**Step 1 — Identify the Value (< 5 min)**  
What binary does the run key point to? Is the path in a temp or user-writable location?  
Is the binary signed? Submit hash to VirusTotal.

**Step 2 — Process That Wrote the Key**  
Was it a recently executed suspicious process (matches GEN-EX-001/002)?

**Step 3 — Remove and Scan**  
Delete the run key via MDE Live Response. Run full AV scan on the pointed binary.

---

## Response Actions
- [ ] Delete the malicious run key
- [ ] Quarantine or delete the pointed binary
- [ ] Scan for additional persistence (scheduled tasks, services)
- [ ] Review for C2 connections from the persistent process

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Legitimate software installers | Add signed installer hashes to ApprovedInstallers watchlist |

## References
- [MITRE T1547.001](https://attack.mitre.org/techniques/T1547/001/)
