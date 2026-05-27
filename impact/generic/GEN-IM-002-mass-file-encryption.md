# GEN-IM-002 — Impact: Mass File Encryption in Progress

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IM-002` |
| **MITRE Technique** | T1486 — Data Encrypted for Impact |
| **Sector** | Generic |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` (MDE) |

## Description
Rapid mass file modification — signature of active ransomware encryption. GEN-IM-001 (shadow copy deletion) should have fired 30–60 seconds before this alert. If GEN-IM-001 was missed or disabled, this rule provides a secondary catch. MDE's Controlled Folder Access should have blocked this — if this alert fires, either CFA is not enabled or the ransomware bypassed it.

## Microsoft Sentinel KQL
```kql
// GEN-IM-002 | Frequency: 5m | Lookback: 5m
DeviceFileEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "FileModified"
| summarize FileCount=count(), Folders=dcount(FolderPath), SampleFiles=make_set(FileName,5)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(TimeGenerated,1m)
| where FileCount > 100
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","OneDrive.exe","BackupAgent.exe","robocopy.exe","xcopy.exe")
| extend AlertTitle = strcat("ACTIVE RANSOMWARE ENCRYPTION on ", DeviceName, " — ", FileCount, " files/min")
```

## Defender XDR / MDE — Controlled Folder Access
Enable in MDE: Security settings → Attack surface reduction → Controlled Folder Access → **Block**.
This prevents ransomware from modifying files in protected folders and triggers a native MDE alert.

## Investigation Guide
**Step 1:** ISOLATE IMMEDIATELY. This is active ransomware. Notify SOC Manager.
**Step 2:** Check if GEN-IM-001 fired earlier on the same device — confirms ransomware chain.
**Step 3:** Run blast radius check (from GEN-IM-001 investigation guide) — multiple devices = outbreak.
**Step 4:** Follow GEN-IM-001 / IR-RANSOMWARE-01 playbook in full.

## Response Actions
Same as GEN-IM-001 — Ransomware Response. This is an active encryption event.
- [ ] Isolate ALL affected hosts immediately
- [ ] Activate BCP — notify customer operations
- [ ] Notify NCSC and ICO as applicable

## References - [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
