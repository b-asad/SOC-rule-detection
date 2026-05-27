# GEN-DE-005 — Defense Evasion: DLL Side-Loading

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DE-005` |
| **MITRE Tactic** | Defense Evasion / Persistence |
| **MITRE Technique** | T1574.002 — Hijack Execution Flow: DLL Side-Loading |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceImageLoadEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

A legitimate, signed application loads a malicious DLL by placing it in the application's search path. Because the DLL is loaded by a legitimate process, traditional AV and EDR may not flag the DLL's behaviour. Commonly used by nation-state actors (APT groups loading implants via legitimate AV, remote access, or CRM software).

---

## Microsoft Sentinel KQL

```kql
// GEN-DE-005 | Frequency: 5m | Lookback: 5m
DeviceImageLoadEvents
| where TimeGenerated >= ago(5m)
| where not(InitiatingProcessFolderPath has_any ("windows\\system32","windows\\syswow64","program files"))
| where FileName endswith ".dll"
| where not(FolderPath has_any ("windows\\system32","windows\\syswow64","program files","winsxs"))
| where SHA1 != ""  // Only capture if hash is available
// Flag unsigned DLLs loaded by legitimate processes
| where not(IsSigned) or SignerHash == ""
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","SenseCE.exe")
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    FileName, FolderPath, SHA256, IsSigned, Signer
| extend AlertTitle = strcat("Unsigned DLL loaded by ", InitiatingProcessFileName, ": ", FileName)
```

---

## Investigation Guide

**Step 1:** Is the DLL in the same directory as the loading application? Side-loading typically places the malicious DLL in the app's folder.
**Step 2:** Submit the DLL SHA256 to VirusTotal — most side-loaded DLLs are malicious.
**Step 3:** What does the DLL do? Analyse behaviour via MDE file analysis or sandbox detonation.

---

## Response Actions
- [ ] Quarantine the malicious DLL
- [ ] Block SHA256 in MDE custom indicators
- [ ] If loaded by a widely-deployed application: check all other instances of that app

## References - [MITRE T1574.002](https://attack.mitre.org/techniques/T1574/002/)
