# GEN-IM-002 — Data Encrypted for Impact: Mass File Encryption

| Field | Value |
|-------|-------|
| Rule ID | GEN-IM-002 |
| Tactic | Impact |
| Technique | T1486 — Data Encrypted for Impact |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceFileEvents` (MDE) |

## Description
Rapid mass file modification with high entropy writes or consistent file extension changes — the signature of ransomware encryption. MDE's built-in ransomware protection should catch this before this rule fires; this rule provides a secondary detection layer.

---

## Microsoft Sentinel KQL
```kql
// GEN-IM-002 | Frequency: 5m | Lookback: 5m
DeviceFileEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "FileModified"
| summarize
    FileCount = count(),
    UniqueFolders = dcount(FolderPath),
    SampleFiles = make_set(FileName, 5)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(TimeGenerated, 1m)
| where FileCount > 100
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","SenseCE.exe","OneDrive.exe","BackupAgent.exe","robocopy.exe")
| extend AlertTitle = "Mass File Modification — Possible Ransomware Encryption"
```

---

## Defender for Endpoint — Native Ransomware Protection
Ensure **Controlled Folder Access** is enabled in MDE:
- Security Center → Device Configuration → Endpoint Protection → Controlled Folder Access → **Enabled**
- This blocks unauthorised processes from modifying files in protected folders.

---

## Investigation Guide

**Step 1:** Confirm mass modification is not a backup/indexing job.  
**Step 2:** Check file extensions — are they being replaced with unknown extensions (`.lockbit`, `.encrypted`, `.enc`)?  
**Step 3:** Run GEN-IM-001 simultaneously — shadow copy deletion usually precedes encryption.  
**Step 4:** If confirmed: follow GEN-IM-001 response procedure — treat as active ransomware.

---

## Response Actions
Same as GEN-IM-001 — Ransomware Response.

## References
- [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
