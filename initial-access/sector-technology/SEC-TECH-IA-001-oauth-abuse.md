# SEC-TECH-IA-001 — Technology: OAuth Application Abuse / Consent Phishing

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-TECH-IA-001` |
| **MITRE Technique** | T1528 — Steal Application Access Token |
| **Sector** | Technology |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `AuditLogs` · `CloudAppEvents` (MCAS) |

## Description
A user grants OAuth consent to a malicious or suspicious third-party application requesting broad permissions (mail read, files read/write, user profile). Consent phishing bypasses MFA by obtaining persistent access tokens. Technology companies are targeted due to valuable source code, API keys, and cloud infrastructure access.

## Microsoft Sentinel KQL
```kql
// SEC-TECH-IA-001 | Frequency: 5m | Lookback: 5m
AuditLogs
| where TimeGenerated >= ago(5m)
| where OperationName in ("Consent to application","Add OAuth2PermissionGrant")
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Permissions = tostring(AdditionalDetails)
| where Permissions has_any ("mail.read","files.readwrite","user.read.all","directory.readwrite","calendars.readwrite","offline_access")
| project TimeGenerated, ConsentedBy, AppName, Permissions, Result
| extend AlertTitle = strcat("OAuth Consent: ", AppName, " granted by ", ConsentedBy)
| extend RiskNote = "Revoke consent if app is not from approved vendor list"
```

## Investigation Guide
**Step 1:** Is the app in the approved OAuth application catalogue?
**Step 2:** What permissions were granted? `mail.read` + `offline_access` = persistent email monitoring.
**Step 3:** Revoke the consent immediately and check what data was accessed.
**Step 4:** Run CloudAppEvents for any data access using the granted token.

## Response Actions
- [ ] Revoke OAuth consent — Azure portal → Enterprise applications → [app] → Revoke permissions
- [ ] Check for data accessed using the granted token
- [ ] Block the application tenant-wide if confirmed malicious
- [ ] Enforce admin consent policy for high-permission OAuth apps

## References - [MITRE T1528](https://attack.mitre.org/techniques/T1528/)
