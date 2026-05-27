# GEN-IA-005 — Initial Access: Spearphishing Link

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IA-005` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1566.002 — Spearphishing Link |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 · Defender XDR |
| **Log Source** | `UrlClickEvents` · `EmailEvents` · `EmailUrlInfo` (MDO) |
| **Created** | May 2026 |

---

## Description

Detects users clicking malicious URLs delivered via email — the most common delivery mechanism for credential phishing, AiTM proxy sites, and drive-by malware downloads. MDO's Safe Links rewrites and tracks all URLs; the `UrlClickEvents` table captures every click and its threat verdict.

Covers both post-delivery URL clicks (where Safe Links identified the threat after delivery) and clicks on URLs that were initially clean but became malicious (time-of-click detonation).

---

## Microsoft Sentinel KQL

```kql
// GEN-IA-005 | Frequency: 5m | Lookback: 5m
UrlClickEvents
| where TimeGenerated >= ago(5m)
| where ActionType in ("ClickAllowed","ClickBlocked")
| where ThreatTypes != "" or IsClickedThrough == true
| project TimeGenerated, AccountUpn, Url, ActionType, ThreatTypes,
    IsClickedThrough, Workload, IPAddress
| extend ClickedThrough = iff(ActionType == "ClickAllowed" and IsClickedThrough, "YES — User proceeded past warning", "No")
| extend AlertTitle = strcat("Phishing Link Click: ", AccountUpn, " → ", Url)
| extend RiskNote = iff(ActionType == "ClickAllowed", "HIGH RISK — user may have entered credentials", "Click blocked by Safe Links")
```

---

## Defender for Office 365 — Full Investigation Queries

```kql
// Find the original email containing the malicious URL
EmailUrlInfo
| where Timestamp >= ago(24h) | where Url == "<URL_FROM_ALERT>"
| join kind=inner (EmailEvents | where Timestamp >= ago(24h)
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction
) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url, DeliveryAction
```

```kql
// How many users clicked the same URL? (campaign scope)
UrlClickEvents
| where Timestamp >= ago(24h)
| where Url == "<URL_FROM_ALERT>" or Url startswith "<URL_DOMAIN_FROM_ALERT>"
| distinct AccountUpn, Url, ActionType, Timestamp
```

---

## Investigation Guide

**Step 1 — Was the click allowed? (0–5 min)**
If `ActionType == "ClickAllowed"` AND `IsClickedThrough == true`: user may have entered credentials on the phishing page. Treat as P1 credential compromise — run GEN-IA-002 checks immediately.

**Step 2 — What did the URL lead to? (5–15 min)**
Submit the URL to VirusTotal and URLScan.io. Is it a credential phishing page? AiTM proxy? Malware download?

**Step 3 — Post-click account activity (15–30 min)**
```kql
SigninLogs | where UserPrincipalName == "<CLICKED_USER>"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, IPAddress, AppDisplayName, ResultType, ConditionalAccessStatus,
    City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| order by TimeGenerated desc
```
New sign-in from unexpected IP immediately after click = credential theft confirmed.

---

## Response Actions
- [ ] If credentials entered: revoke sessions, reset password, force MFA re-enrolment immediately
- [ ] Block the phishing domain in MDO and Conditional Access
- [ ] Find all users who clicked the same URL — scope the campaign
- [ ] Soft-delete the phishing email from all recipient mailboxes (MDO Threat Explorer)

## References
- [MITRE T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [Microsoft: URL click events](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
