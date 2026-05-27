# SEC-FS-IA-001 — Financial Services: BEC Wire Transfer Fraud Indicators

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-FS-IA-001` |
| **MITRE Tactic** | Initial Access / Impact |
| **MITRE Technique** | T1657 — Financial Theft |
| **Sector** | **Financial Services** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 · Defender for Cloud Apps |
| **Log Source** | `EmailEvents` (MDO) · `OfficeActivity` (M365 UAL) · `SigninLogs` |
| **Sector Context** | Banks, asset managers, payment firms, corporate treasury, finance teams |
| **Created** | May 2026 |

---

## Description

Detects Business Email Compromise (BEC) indicators targeting financial services: wire transfer requests from lookalike domains, unusual payment instruction emails from senior executive accounts, supplier bank detail change requests, and email forwarding rules on finance team accounts.

BEC causes more financial loss than any other cybercrime type. Financial services firms are the highest-value targets. A single successful BEC can result in losses of millions of pounds. Speed of detection is critical — wire transfers may be reversible within hours if the recipient bank is notified promptly.

**Regulatory:** FCA PS21/3 (operational resilience), UK Finance Fraud Reporting, SWIFT Customer Security Programme.

---

## Microsoft Sentinel KQL

```kql
// SEC-FS-IA-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
// Detection 1: Inbound email from lookalike / typosquat domain with payment keywords
let FinancialKeywords = dynamic([
    "wire transfer","urgent payment","bank transfer","swift","iban",
    "invoice","payment instruction","account details","change of bank",
    "new bank details","supplier payment","beneficiary","remittance",
    "funds transfer","payment approval","authorize payment","pay immediately"
]);
let InternalDomains = (_GetWatchlist('InternalEmailDomains') | project SearchKey);
EmailEvents
| where TimeGenerated >= ago(5m)
| where DeliveryAction != "Blocked"
| where Subject has_any (FinancialKeywords) or
    (AdditionalFields has_any (FinancialKeywords))
| where not(SenderFromDomain in~ (InternalDomains))
// Flag domains that look like internal domains (typosquatting)
| extend DomainSimilarity = iff(
    SenderFromDomain contains_cs "corp" or
    SenderFromDomain matches regex @"[0-9]",  // Numbers in domain = suspicious
    "PossibleTyposquat", "External"
)
| where DomainSimilarity == "PossibleTyposquat"
    or RecipientEmailAddress has_any ("cfo","finance","treasury","payments","accounts","ap@","ar@")
| project
    TimeGenerated, SenderFromAddress, SenderFromDomain,
    RecipientEmailAddress, Subject, ThreatTypes,
    DomainSimilarity, DeliveryAction, DeliveryLocation
| extend AlertTitle = strcat("BEC Risk: Payment keyword email from ", SenderFromDomain)
| extend FinancialRisk = "Immediate: Contact finance team to freeze any pending payments from this email"
```

---

## Defender for Office 365 — Email Hunting

```kql
// Find all emails with payment keywords from external senders in last 7 days
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryAction != "Blocked"
| where Subject has_any (
    "wire transfer","urgent payment","bank transfer","new account details",
    "change bank","payment instruction","invoice","swift","iban"
)
| where SenderFromDomain !in~ (<INTERNAL_DOMAINS>)
| project
    Timestamp, SenderFromAddress, SenderFromDomain,
    RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1 — Contact Finance Team Immediately (< 5 min)**
Call (not email) the finance team: "Has anyone processed or approved a payment based on recent email instruction?"
If yes: contact your bank's fraud team immediately — wire transfers may still be reversible.

**Step 2 — Validate the Email Domain (5–15 min)**
Check the sender domain WHOIS: when was it registered? Who registered it?
Compare the sender domain visually and character-by-character to your customer's internal domains.
Common typosquatting: `cornpany.com` vs `company.com`, `companyname.co` vs `companyname.com`.

**Step 3 — Executive Account Compromise Check (15–30 min)**
Was the email sent FROM a legitimate internal account? If so, run GEN-IA-002 (impossible travel) and GEN-CO-001 (forwarding rule) checks on that account — the executive's account may be compromised.

---

## Response Actions
**Immediate**
- [ ] Contact finance team by phone — freeze any pending payments from email instruction
- [ ] If payment already sent: contact bank fraud team IMMEDIATELY — reversal window is very short
- [ ] Block the sender domain in MDO
- [ ] Notify Compliance Officer

**If payment sent (time-critical)**
- [ ] Contact your bank's fraud line and instruct them to initiate a SWIFT recall
- [ ] Contact the recipient bank if known — request funds hold
- [ ] File fraud report with Action Fraud (UK): 0300 123 2040
- [ ] Contact UK Finance Fraud Intelligence Bureau

## References
- [MITRE T1657](https://attack.mitre.org/techniques/T1657/)
- [Action Fraud: BEC reporting](https://www.actionfraud.police.uk)
- [UK Finance: Fraud reporting](https://www.ukfinance.org.uk/fraud)
