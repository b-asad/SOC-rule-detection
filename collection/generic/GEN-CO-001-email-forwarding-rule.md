# GEN-CO-001 — Collection: Malicious Email Auto-Forwarding Rule

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CO-001` |
| **MITRE Tactic** | Collection |
| **MITRE Technique** | T1114.003 — Email Collection: Email Forwarding Rule |
| **Sector** | **Generic** — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Office 365 · Defender for Cloud Apps |
| **Log Source** | `OfficeActivity` (M365 UAL) · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |

---

## Description

Detects creation of an inbox rule that auto-forwards or redirects emails to an external address. This is the primary persistence mechanism in Business Email Compromise (BEC) — after compromising an account, the attacker creates a forwarding rule to monitor the victim's email without maintaining an active session. Finance team, HR, and executive mailboxes are the highest-value targets.

MDO has a built-in alert policy for this — ensure it is enabled. This Sentinel rule provides an additional detection with richer context and cross-tenant hunting capability.

---

## Microsoft Sentinel KQL

```kql
// GEN-CO-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
// Playbook: PB-REVOKE-SESSION-AND-DELETE-RULE
OfficeActivity
| where TimeGenerated >= ago(5m)
| where Operation in (
    "New-InboxRule","Set-InboxRule","UpdateInboxRules",
    "Set-Mailbox"  // Set-Mailbox -ForwardingSmtpAddress
)
| where Parameters has_any (
    "ForwardTo","ForwardAsAttachmentTo","RedirectTo",
    "ForwardingSmtpAddress","ForwardingAddress",
    "DeleteMessage","MarkAsRead","MoveToFolder"
)
| extend RuleDetails = tostring(Parameters)
| extend ForwardDomain = extract(@"@([\w.-]+)", 1, RuleDetails)
| where isnotempty(ForwardDomain)
// Exclude known internal domains — add customer domains to TrustedEmailDomains watchlist
| where not(ForwardDomain in~ (_GetWatchlist('TrustedEmailDomains') | project SearchKey))
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    RuleDetails,
    ForwardDomain,
    OfficeObjectId
| extend AlertTitle = strcat("External Email Forwarding Rule Created by ", UserId)
| extend Severity = "High"
| extend BECRisk = "Attacker may be monitoring this mailbox. Check for financial requests and data exposure."
```

**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0` · Playbook: `PB-REVOKE-SESSION-AND-DELETE-RULE`

---

## Defender XDR — Advanced Hunting

```kql
// GEN-CO-001 | Run: Every hour | Category: Collection | Severity: Medium
CloudAppEvents
| where Timestamp >= ago(1h)
| where ActionType == "New-InboxRule"
| where RawEventData has_any (
    "ForwardTo","ForwardAsAttachmentTo","RedirectTo","ForwardingSmtpAddress"
)
| extend ForwardTarget = tostring(parse_json(RawEventData).Parameters.ForwardTo)
| where isnotempty(ForwardTarget)
| project
    Timestamp, AccountDisplayName, AccountUpn, IPAddress, Country,
    ActionType, ForwardTarget, RawEventData
| order by Timestamp desc
```

---

## Defender for Office 365 — MDO Alert Policy

**Enable these built-in MDO alerts** (Security & Compliance → Policies → Alert policies):
- ✅ **Email forwarding rule created to external domain** ← direct correlation
- ✅ **Suspicious email forwarding activity** ← volume-based detection
- ✅ **Messages have been delayed** (identifies compromised mail flow)

**MDO Hunting — check current forwarding rules for all users:**
```kql
// Check for all active external forwarding rules in the tenant
// Run in Defender XDR → Hunting
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType == "New-InboxRule"
| where RawEventData has_any ("ForwardTo","ForwardingSmtpAddress")
| summarize
    RuleCount = count(),
    LastCreated = max(Timestamp)
    by AccountUpn, tostring(parse_json(RawEventData).Parameters.ForwardTo)
| order by LastCreated desc
```

---

## Defender for Cloud Apps — CASB Policy

Create an Activity Policy in MCAS:
- **Activity:** New inbox forwarding rule
- **Filter:** Forward/Redirect destination = External domain
- **Alert severity:** High
- **Governance action:** Notify SOC (immediate) + optionally Suspend user (with customer pre-approval)

---

## Investigation Guide

**Step 1 — Validate the Rule (< 5 min)**
Contact the user's direct manager by phone (not email): Is the forwarding to a legitimate personal or business address?
If the user cannot confirm it: treat as BEC incident immediately.

**Step 2 — Account Compromise Indicators (5–20 min)**
```kql
// Was there a suspicious sign-in before the rule was created?
SigninLogs
| where UserPrincipalName == "<USER_FROM_ALERT>"
| where TimeGenerated >= ago(7d)
| project
    TimeGenerated, IPAddress,
    City    = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    AppDisplayName, ResultType, ConditionalAccessStatus,
    AuthenticationRequirement
| order by TimeGenerated desc
```

Look for: sign-in from new country/IP in the hours before the rule was created, MFA prompt at unusual time, successful sign-in from anonymous proxy.

**Step 3 — What Has Been Forwarded (20–40 min)**
```kql
// Assess what emails were collected by the attacker
EmailEvents
| where SenderFromAddress == "<USER_EMAIL>"
    or RecipientEmailAddress == "<USER_EMAIL>"
| where Timestamp >= ago(7d)
| where DeliveryAction != "Blocked"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes
| order by Timestamp desc
```

For finance team accounts: check for any emails containing wire transfer instructions, invoice approvals, supplier payment changes, or executive payment requests.

**Step 4 — Additional Inbox Rules (40–50 min)**
```kql
// Did the attacker create other rules to hide their tracks?
OfficeActivity
| where UserId == "<USER_FROM_ALERT>"
| where TimeGenerated >= ago(7d)
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| project TimeGenerated, Operation, Parameters, ClientIP
```

Common cover-track rules: delete emails from the compromised account's sent items, mark reply emails as read, move specific emails to obscure folders.

---

## Response Actions
**Immediate (P1 — within 15 minutes)**
- [ ] **Delete the forwarding rule** — Exchange Online admin → Mailboxes → [user] → Manage email apps / inbox rules
- [ ] **Revoke all active sessions** — Entra ID portal → Users → [user] → Revoke sessions
- [ ] **Reset password** and force MFA re-enrolment
- [ ] **Notify user's manager and finance team** if the user is in a financial role
- [ ] **Audit sent items** — check for BEC payment instruction emails sent from the compromised account

**Within 1 Hour**
- [ ] Check for additional inbox rules (delete, mark-as-read, hide rules)
- [ ] Review all emails sent from the account in the past 7 days
- [ ] Alert the customer's finance team to verify any recent payment instructions or supplier detail changes
- [ ] Submit the attacker's IP to threat intelligence feeds

**Recovery**
- [ ] Enforce Conditional Access policy requiring compliant device for email access
- [ ] Enable continuous access evaluation (CAE) for the user
- [ ] Conduct phishing awareness session with the affected user's team

---

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Legitimate out-of-office forwarding to personal email | Verify with user and manager; add approved personal domain to `TrustedEmailDomains` watchlist with expiry date |
| Contractor forwarding work email to corporate account | Document as approved; add contractor's corporate domain to `TrustedEmailDomains` watchlist |

---

## References
- [MITRE T1114.003](https://attack.mitre.org/techniques/T1114/003/)
- [Microsoft: Detect and remediate BEC](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account)
- [NCSC: BEC guidance](https://www.ncsc.gov.uk/collection/business-email-compromise)
