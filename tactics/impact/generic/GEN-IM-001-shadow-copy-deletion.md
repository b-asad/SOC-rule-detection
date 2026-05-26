# GEN-IM-001 — Inhibit System Recovery: Shadow Copy Deletion

| Field | Value |
|-------|-------|
| Rule ID | GEN-IM-001 |
| Tactic | Impact |
| Technique | T1490 — Inhibit System Recovery |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceProcessEvents` (MDE) |

## Description
Deletion of Windows Volume Shadow Copies via `vssadmin`, `wmic`, `PowerShell`, `bcdedit`, or `wbadmin`. This is the most reliable ransomware precursor — virtually every major ransomware family deletes shadow copies immediately before encryption. **Zero tolerance: never suppress, never raise threshold.**

---

## Microsoft Sentinel KQL
```kql
// GEN-IM-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0 — NEVER CHANGE
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows","Delete Shadows"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("shadowcopy delete","ShadowCopy delete","Win32_ShadowCopy"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Win32_ShadowCopy","Delete()","vssadmin"))
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","bootstatuspolicy ignoreallfailures"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete catalog")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```
**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0` · Playbook: `PB-RANSOMWARE-RESPONSE` (auto-isolate enabled)

---

## Defender XDR — Advanced Hunting
```kql
// GEN-IM-001 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows","Delete Shadows"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("shadowcopy delete","Win32_ShadowCopy"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Win32_ShadowCopy","vssadmin"))
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete catalog")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

---

## Defender for Endpoint — Automated Response
Enable the following MDE policies:
- **Attack Surface Reduction rule:** Block process creations originating from PSExec and WMI commands
- **Tamper protection:** Enabled on all endpoints
- **Auto-investigation:** Enable auto-remediation for ransomware indicators

---

## Investigation Guide

> ⚠️ **TREAT AS ACTIVE RANSOMWARE. Isolate first, investigate second.**

**Step 1 — Isolate Immediately (< 5 min)**
Isolate via MDE. Notify SOC Manager and customer CISO by phone. Activate IR-RANSOMWARE-01 playbook in SOAR.

**Step 2 — Blast Radius (5–15 min)**
```kql
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows"
| distinct DeviceName, AccountName, Timestamp
| order by Timestamp asc
```
Multiple hosts = active outbreak. Consider emergency network segmentation.

**Step 3 — Pre-Encryption Activity (15–30 min)**
```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where ProcessCommandLine has_any ("net stop","sc stop","taskkill","icacls","cipher /w","sdelete","wbadmin","bcdedit")
| project Timestamp, FileName, ProcessCommandLine, AccountName | order by Timestamp asc
```

**Step 4 — Encryption In Progress**
```kql
DeviceFileEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(30m)
| where ActionType == "FileModified"
| summarize FileCount=count() by bin(Timestamp,1m), FolderPath
| where FileCount > 50
```

**Step 5 — Ransom Note**
```kql
DeviceFileEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(1h)
| where FileName has_any ("README","DECRYPT","HOW_TO","ransom","RECOVER","YOUR_FILES","RESTORE")
| project Timestamp, FileName, FolderPath
```

---

## Response Actions
**Immediate**
- [ ] Isolate ALL affected hosts — MDE
- [ ] Disconnect NAS / network shares from network
- [ ] Alert: SOC Manager → Head of Security Services → Customer CISO (phone)
- [ ] Activate BCP with customer
- [ ] Do NOT reboot — preserve memory forensics
- [ ] Do NOT pay ransom — advise customer strongly

**Within 1 hour**
- [ ] Confirm clean backup restore point (verify backups NOT encrypted)
- [ ] Notify NCSC (UK) and ICO (if personal data involved — 72h GDPR window)
- [ ] Identify patient zero (first host, first alert)
- [ ] Identify ransomware family from ransom note / file extension IOCs

**Recovery**
- [ ] Restore from last known-clean backup
- [ ] Reset ALL domain credentials — assume full compromise
- [ ] Reset KRBTGT password twice (24–48h apart)
- [ ] Rebuild from clean images — do not restore infected images
- [ ] Post-incident review within 5 business days

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Backup software cleaning old shadows | Verify backup agent hash; suppression requires CISO sign-off, max 4h |
| IT admin manual cleanup | Investigate regardless — confirm with admin before suppressing |

## References
- [MITRE T1490](https://attack.mitre.org/techniques/T1490/)
- [NCSC: Ransomware response](https://www.ncsc.gov.uk/ransomware/home)
