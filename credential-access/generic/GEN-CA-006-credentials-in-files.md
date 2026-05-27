# GEN-CA-006 — Credential Access: Credentials in Files / Environment Variables

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CA-006` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1552.001 — Unsecured Credentials: Credentials in Files |
| **Sector** | Generic — All Customers |
| **Severity** | **Medium** |
| **Priority** | **P2** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Attacker searching for credentials stored in plaintext files — `.env` files, configuration files, PowerShell scripts, bash history, cloud credential files (`.aws/credentials`, `.azure/accessTokens.json`). Common post-exploitation step to find lateral movement or cloud escalation credentials.

---

## Microsoft Sentinel KQL

```kql
// GEN-CA-006 | Frequency: 5m | Lookback: 15m
DeviceProcessEvents
| where TimeGenerated >= ago(15m)
| where (
    // grep/findstr searching for credentials
    (FileName in~ ("findstr.exe","grep","grep.exe","rg.exe") and ProcessCommandLine has_any (
        "password","passwd","credential","secret","api_key","apikey","token","connectionstring",
        "pwd=","pass=","username=","user=","login="
    ))
    // Type/cat of sensitive file types
    or (FileName in~ ("cmd.exe","powershell.exe") and ProcessCommandLine has_any (
        ".env","credentials","secrets.json","accessTokens","config.json","web.config",
        ".aws/credentials",".azure","vault","keystore"
    ) and ProcessCommandLine has_any ("type ","cat ","gc ","Get-Content","more "))
    // PowerShell searching environment variables for credentials
    or (FileName in~ ("powershell.exe") and ProcessCommandLine has_any (
        "Get-ChildItem Env:","[Environment]::GetEnvironmentVariable","$env:","dir env:"
    ) and ProcessCommandLine has_any ("password","secret","key","token"))
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
| extend AlertTitle = "Credential File Search Detected"
```

---

## Investigation Guide

**Step 1:** Was this an authorised admin task or post-exploitation credential hunting?
**Step 2:** What files did the search find? Were any credentials read?
**Step 3:** If credentials found: identify all systems the credentials provide access to and rotate them.

---

## Response Actions
- [ ] Rotate any credentials that may have been exposed
- [ ] Remediate the underlying misconfiguration — credentials should never be in plaintext files
- [ ] Implement secrets management (Azure Key Vault, HashiCorp Vault)

## References - [MITRE T1552.001](https://attack.mitre.org/techniques/T1552/001/)
