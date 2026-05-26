# GEN-CO-001 — Collection: Malicious Email Forwarding Rule

| Field | Value |
|-------|-------|
| Rule ID | GEN-CO-001 |
| Tactic | Collection |
| Technique | T1114.003 — Email Collection: Email Forwarding Rule |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Office 365 · Defender for Cloud Apps |
| Log Source | `OfficeActivity` (M365 UAL), `CloudAppEvents` |

## Description
Inbox forwarding rule created to auto-forward emails to an external address. Classic Business Email Compromise (BEC) persistence mechanism — attacker monitors mailbox after initial account compromise without maintaining an active session.

---

## Microsoft Sentinel KQL
```kql
// GEN-CO-001 | Frequency: 5m | Lookback: 5m
OfficeActivity
| where TimeGenerated >= ago(5m)
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where Parameters has_any ("ForwardTo","ForwardAsAttachmentTo","RedirectTo")
| extend RuleDetails = tostring(Parameters)
| extend ForwardDomain = extract(@"ForwardTo.*?@([\w.-]+)", 1, RuleDetails)
| where isnotempty(ForwardDomain)
| project TimeGenerated, UserId, ClientIP, Operation, RuleDetails, ForwardDomain
```

---

## Defender for Cloud Apps — CASB Policy
Create a CASB Activity Policy:
- Activity: New mail forwarding rule
- Filter: Forward/Redirect to External domain
- Alert: High severity → notify SOC
- Governance: Suspend user (with customer pre-approval)

---

## Defender for Office 365 — Alert Policy
Enable built-in MDO alert: **Email forwarding rule created to external domain**  
Security & Compliance → Policies → Alert policies → Enable this alert.

---

## Investigation Guide

**Step 1 — Validate Rule (< 10 min)**  
Is the forwarding destination a known legitimate address (e.g., personal email confirmed by user)?  
If unknown: treat as BEC incident.

**Step 2 — Account Compromise Indicators**
```kql
SigninLogs | where UserPrincipalName == "<UPN>" | where TimeGenerated >= ago(7d)
| project TimeGenerated, IPAddress, tostring(LocationDetails.city), AppDisplayName, ResultType
| order by TimeGenerated desc
```
Was there a recent login from an unusual location before the rule was created?

**Step 3 — What Was Forwarded**  
Check if any sensitive emails were forwarded: financial discussions, executive communications, HR data.

---

## Response Actions
- [ ] Delete the forwarding rule immediately
- [ ] Revoke all active sessions — Entra ID
- [ ] Reset password + MFA re-enrolment
- [ ] Review all emails sent/received since rule creation
- [ ] Check for additional inbox rules (hide, delete, mark-as-read patterns)
- [ ] Notify customer — assess BEC financial risk

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Legitimate out-of-office external forwarding | Verify with user's manager; document approved rules in exclusions list |

## References
- [MITRE T1114.003](https://attack.mitre.org/techniques/T1114/003/)
