# SEC-TECH-CA-001 — Technology: Code Signing Certificate / Secret Access

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-TECH-CA-001` |
| **MITRE Technique** | T1552.004 — Credentials in Files: Private Keys |
| **Sector** | Technology |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` · `DeviceProcessEvents` (MDE) |

## Description
Access to or exfiltration of code signing certificates, private keys, API secrets, or deployment credentials. Technology companies hold some of the most valuable secrets — code signing certificates allow attackers to sign malware as trusted software, API keys grant cloud infrastructure access, and deployment credentials enable supply chain attacks.

## Microsoft Sentinel KQL
```kql
// SEC-TECH-CA-001 | Frequency: 5m | Lookback: 15m
DeviceFileEvents
| where TimeGenerated >= ago(15m)
| where FileName has_any (".pfx",".p12",".pem",".key",".cer",".crt",".p7b")
    or (FileName has_any ("secret","credential","token","api_key","private_key","cert") and FileName has_any (".env",".json",".yaml",".yml",".config",".xml",".txt"))
| where ActionType in ("FileCreated","FileCopied","FileModified")
| where FolderPath !has_any ("backup","archive","\node_modules\")
| where InitiatingProcessFileName !in~ ("git","vault","aws","az","gcloud","keytool","certutil","signtool")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| extend AlertTitle = strcat("Secret/Cert File Access: ", FileName)
```

## Investigation Guide
**Step 1:** What certificate or secret was accessed? What system does it protect?
**Step 2:** Was the file copied to an external location? Check DeviceNetworkEvents.
**Step 3:** If code signing cert: has anything been signed with it since? Check certificate transparency logs.
**Step 4:** Revoke and replace the compromised certificate/secret immediately.

## Response Actions
- [ ] Revoke the compromised certificate/API key/secret immediately
- [ ] Audit any binaries signed with the compromised certificate
- [ ] Rotate all secrets in the affected vault/keystore
- [ ] Notify customers if a code signing certificate was compromised — signed software may appear trusted

## References - [MITRE T1552.004](https://attack.mitre.org/techniques/T1552/004/)
