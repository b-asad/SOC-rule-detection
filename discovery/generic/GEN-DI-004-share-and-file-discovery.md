# GEN-DI-004 — Discovery: Network Share and File System Discovery

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DI-004` |
| **MITRE Tactic** | Discovery |
| **MITRE Technique** | T1135 / T1083 — Network Share Discovery / File and Directory Discovery |
| **Sector** | Generic — All Customers |
| **Severity** | **Medium** |
| **Priority** | **P2** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Attacker enumerating network shares and file system contents to locate valuable data (financial records, source code, credentials, customer databases) before staging for exfiltration. Commonly follows AD enumeration and precedes data collection.

---

## Microsoft Sentinel KQL

```kql
// GEN-DI-004 | Frequency: 10m | Lookback: 10m
DeviceProcessEvents
| where TimeGenerated >= ago(10m)
| where (
    // Network share enumeration
    (FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has_any ("view","use","share"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
        "Get-SmbShare","Get-WmiObject Win32_Share","net view","[Net.Dns]"
    ))
    // File system discovery — recursive dir/ls searching for valuable files
    or (FileName in~ ("cmd.exe","powershell.exe") and ProcessCommandLine has_any (
        "dir /s","Get-ChildItem -Recurse","ls -la","find /","Get-ChildItem"
    ) and ProcessCommandLine has_any (
        "*.pdf","*.doc","*.xls","*.csv","password","credential","secret","backup","finance"
    ))
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

---

## Investigation Guide

**Step 1:** What shares or directories are being enumerated? Are they sensitive (Finance, HR, Legal, IT)?
**Step 2:** Correlate with collection rules — is bulk file access occurring on the same device?
**Step 3:** Is this the same device that performed AD enumeration (GEN-DI-002)? If so: attacker is mapping the full attack path.

---

## Response Actions
- [ ] If enumeration on a workstation (not a management server): investigate as compromised host
- [ ] Review share permissions — are sensitive shares accessible to all domain users?

## References - [MITRE T1135](https://attack.mitre.org/techniques/T1135/) | [MITRE T1083](https://attack.mitre.org/techniques/T1083/)
