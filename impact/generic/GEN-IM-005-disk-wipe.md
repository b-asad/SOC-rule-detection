# GEN-IM-005 — Impact: Disk Wipe / Data Destruction

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IM-005` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | T1561 / T1485 — Disk Wipe / Data Destruction |
| **Sector** | Generic — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Commands used to destroy data — `format`, `cipher /w` (overwrite), `sdelete`, `diskpart clean`, MBR overwrite, or mass file deletion. More destructive than ransomware (no recovery path), used by nation-state wipers (NotPetya, Shamoon, HermeticWiper, WhisperGate) and as a final-stage destructive payload.

---

## Microsoft Sentinel KQL

```kql
// GEN-IM-005 | Frequency: 5m | Lookback: 5m | Threshold: > 0 — ZERO TOLERANCE
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (
    // diskpart destructive operations
    (FileName =~ "diskpart.exe" and ProcessCommandLine has_any ("clean","format","delete volume","delete partition"))
    // cipher /w — secure overwrite
    or (FileName =~ "cipher.exe" and ProcessCommandLine has "/w")
    // sdelete — secure delete
    or (FileName in~ ("sdelete.exe","sdelete64.exe") and ProcessCommandLine has_any ("-s","-r","-p","-z"))
    // format — format drive
    or (FileName =~ "format.com" and ProcessCommandLine has_any ("/fs","/q","/y","c:","d:","e:"))
    // PowerShell mass delete
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
        "Remove-Item -Recurse -Force","rd /s /q","rmdir /s /q",
        "Del /f /s /q","[System.IO.File]::Delete","IO.Directory]::Delete"
    ) and ProcessCommandLine has_any ("C:\\","D:\\","Users","Documents","Windows"))
    // wbadmin delete - destroy backups
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has_any ("delete catalog","delete systemstatebackup"))
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
| extend AlertTitle = strcat("CRITICAL: Data Destruction on ", DeviceName)
| extend Severity = "Critical"
| extend Note = "Zero tolerance — no false positives expected. Treat as active destructive attack."
```

---

## Response Actions
- [ ] Isolate device IMMEDIATELY
- [ ] Preserve forensic image before any further disk activity
- [ ] Notify SOC Manager and customer CISO
- [ ] Assess whether data can be recovered from backups
- [ ] If nation-state indicators: NCSC notification

## References
- [MITRE T1561](https://attack.mitre.org/techniques/T1561/)
- [MITRE T1485](https://attack.mitre.org/techniques/T1485/)
