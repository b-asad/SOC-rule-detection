# GEN-CA-005 — Credential Access: Golden SAML / SAML Token Forgery

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CA-005` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1606.002 — Forge Web Credentials: SAML Tokens |
| **Sector** | Generic — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR |
| **Log Source** | `SigninLogs` · `AuditLogs` · `IdentityLogonEvents` (MDI) |
| **Created** | May 2026 |

---

## Description

Forged SAML tokens allow an attacker with access to the AD FS token signing certificate or the Azure AD Connect service to authenticate as any user — including Global Administrators — without knowing their password or triggering MFA. Used in the SolarWinds/NOBELIUM campaign. Indicators: authentication via SAML from a new device or location with no prior sign-in history, token claims inconsistent with normal user behaviour.

---

## Microsoft Sentinel KQL

```kql
// GEN-CA-005 | Frequency: 5m | Lookback: 1h
// Suspicious SAML authentication: auth via federation with anomalous characteristics
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType == "0"
| where AuthenticationProtocol == "SAML20" or TokenIssuerType == "AzureAD"
| where DeviceDetail == "{}" or tostring(DeviceDetail) == ""  // No device registered = suspicious for SAML
// Correlate with Entra ID Risk
| where RiskLevelAggregated in ("high","medium")
    or RiskEventTypes has_any ("unfamiliarFeatures","anomalousToken","tokenIssuerAnomaly","suspiciousInboxManipulation")
| project TimeGenerated, UserPrincipalName, IPAddress, AuthenticationProtocol,
    RiskLevelAggregated, RiskEventTypes, tostring(DeviceDetail),
    AppDisplayName, TokenIssuerName, ConditionalAccessStatus
| extend AlertTitle = strcat("Suspicious SAML/Federation Auth: ", UserPrincipalName)
| extend Severity = "Critical"
| extend Note = "Check ADFS token signing cert and Azure AD Connect for compromise"
```

---

## Defender for Identity — MDI Alerts

MDI detects Golden SAML precursor activities:
- **Suspected Golden SAML attack** — alert fires when MDI detects the SAML signing cert being exported
- Ensure MDI sensor is on the ADFS server (not just DCs)

---

## Investigation Guide

**Step 1 — Identify the SAML source (0–10 min)**
Is your organisation using ADFS federation or Azure AD direct authentication?
If ADFS: the signing certificate may be compromised. Contact the ADFS admin immediately.

**Step 2 — Scope of forged tokens (10–25 min)**
What accounts authenticated via SAML in the suspicious window?
Check if Global Admin accounts show anomalous activity — Golden SAML enables any-user impersonation.

**Step 3 — ADFS certificate rotation (25–60 min)**
If confirmed: the ADFS token signing certificate must be rotated immediately.
This is a complex procedure — engage Microsoft DART or a specialist IR firm.

---

## Response Actions
- [ ] Revoke all sessions for affected accounts
- [ ] If ADFS compromise confirmed: rotate ADFS token signing and encryption certificates
- [ ] Enable "Protect all users" in Entra ID Protection
- [ ] Consider migrating from ADFS to Entra ID native authentication

## References
- [MITRE T1606.002](https://attack.mitre.org/techniques/T1606/002/)
- [Microsoft: Golden SAML attacks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app)
