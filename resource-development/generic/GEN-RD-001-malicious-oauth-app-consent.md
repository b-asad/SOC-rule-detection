# GEN-RD-001 — Resource Development: Malicious OAuth Application Registered / Consented

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-RD-001` |
| **MITRE Tactic** | Resource Development |
| **MITRE Technique** | T1585.002 — Establish Accounts: Email Accounts / T1528 — Steal Application Access Token |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `AuditLogs` · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |

---

## Description

A new OAuth application registered in the tenant or a consent grant to a third-party application with high permissions — a common technique for establishing persistent access to M365 data (emails, files, contacts) that survives password resets and MFA changes. Attacker registers a malicious app or tricks a user into consenting to one via consent phishing.

This is the "resource development" phase — the attacker is establishing infrastructure within the victim tenant.

---

## Microsoft Sentinel KQL

```kql
// GEN-RD-001 | Frequency: 15m | Lookback: 1h
let HighRiskPerms = dynamic([
    "Mail.Read","Mail.ReadWrite","Mail.Send","MailboxSettings.ReadWrite",
    "Files.Read.All","Files.ReadWrite.All","Sites.Read.All","Sites.ReadWrite.All",
    "Calendars.ReadWrite","Contacts.Read","People.Read.All",
    "User.ReadWrite.All","Group.ReadWrite.All","Directory.ReadWrite.All",
    "offline_access","full_access_as_app"
]);
// Detection A: New app registration with high permissions
AuditLogs
| where TimeGenerated >= ago(1h)
| where OperationName in ("Add application","Add service principal","Add OAuth2PermissionGrant")
| extend Actor       = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName     = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(AdditionalDetails)
| where Permissions has_any (HighRiskPerms)
| project TimeGenerated, Actor, AppName, OperationName, Permissions, Result
| extend AlertTitle = strcat("High-Perm App Created/Consented: ", AppName)
```

```kql
// Detection B: User consent to third-party app with high permissions
AuditLogs
| where TimeGenerated >= ago(1h)
| where OperationName == "Consent to application"
| extend Actor       = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName     = tostring(TargetResources[0].displayName)
| extend Scopes      = tostring(AdditionalDetails[0].value)
| where Scopes has_any (HighRiskPerms)
| project TimeGenerated, Actor, AppName, Scopes, Result
| extend AlertTitle = strcat("High-Risk OAuth Consent: ", AppName, " by ", Actor)
```

---

## Investigation Guide

**Step 1 — Is the app legitimate? (0–10 min)**
Is this a known enterprise application (Salesforce, Okta, ServiceNow) or an unfamiliar name?
Check the application's App ID and publisher in Entra ID — is the publisher verified?

**Step 2 — What permissions were granted? (10–20 min)**
`Mail.Read` + `offline_access` = persistent email monitoring.
`Files.ReadWrite.All` = full file system access.
`Directory.ReadWrite.All` = tenant admin equivalent.

**Step 3 — Revoke and investigate usage (20–40 min)**
Revoke the consent immediately. Check CloudAppEvents for data accessed via this app.

---

## Response Actions
- [ ] Revoke the OAuth consent: Entra ID → Enterprise applications → [app] → Permissions → Revoke admin consent
- [ ] Delete the app registration if attacker-created
- [ ] Check CloudAppEvents for data accessed via the app
- [ ] Enable admin consent policy — require admin approval for all high-permission apps

## References
- [MITRE T1528](https://attack.mitre.org/techniques/T1528/)
- [Microsoft: OAuth consent phishing](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)
