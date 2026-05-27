# GEN-RC-003 — Reconnaissance / Resource Development: Phishing Infrastructure Detected

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-RC-003` |
| **MITRE Tactic** | Reconnaissance / Resource Development |
| **MITRE Technique** | T1583.001 — Acquire Infrastructure: Domains |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 |
| **Log Source** | `ThreatIntelligenceIndicator` · `EmailEvents` (MDO) |
| **Created** | May 2026 |

---

## Description

A newly registered domain typosquatting or impersonating the customer's brand has been detected — a strong indicator that an attacker has set up phishing infrastructure targeting the organisation. Detection uses Microsoft Defender Threat Intelligence and outbound email analysis to identify lookalike domains before they are used.

---

## Microsoft Sentinel KQL

```kql
// GEN-RC-003 | Frequency: 1h | Lookback: 24h
// Requires MDTI or threat intel feed with typosquatting/lookalike data
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(24h)
| where Active == true
| where Tags has_any ("lookalike","typosquat","phishing","brand-abuse","impersonation")
| where DomainName has_any (_GetWatchlist('InternalEmailDomains') | project SearchKey)
    or Description has_any (_GetWatchlist('InternalEmailDomains') | project SearchKey)
| project TimeGenerated, DomainName, Description, Tags, ConfidenceScore, ThreatType
| extend AlertTitle = strcat("Lookalike Domain: ", DomainName)
```

```kql
// Also check MDO: emails from domains similar to internal domains (typosquatting)
EmailEvents
| where TimeGenerated >= ago(24h)
| where DeliveryAction != "Blocked"
| extend InternalDomains = (_GetWatchlist('InternalEmailDomains') | project SearchKey)
// Flag domains with edit distance 1-2 from internal domains (approximate match)
| where SenderFromDomain !in~ (InternalDomains)
    and (SenderFromDomain has_any ("corp","company","inc","ltd","group")
        or strlen(SenderFromDomain) between (toint(strlen(tostring(InternalDomains))) - 3 .. toint(strlen(tostring(InternalDomains))) + 3))
| summarize Count=count() by SenderFromDomain, RecipientEmailAddress
| where Count > 3
| extend AlertTitle = strcat("Possible Lookalike Domain Sending Email: ", SenderFromDomain)
```

---

## Investigation Guide

**Step 1:** Is this domain genuinely a lookalike? (e.g., `c0mpany.com` vs `company.com`)
**Step 2:** Has the domain been used to send emails to your organisation yet? Check EmailEvents.
**Step 3:** Proactive block — add to MDO blocked senders list before any emails arrive.

---

## Response Actions
- [ ] Add lookalike domain to MDO blocked senders list proactively
- [ ] Add to Sentinel TI watchlist for ongoing monitoring
- [ ] Consider domain takedown request via NCSC or registrar abuse team
- [ ] Alert employees to watch for phishing from this domain

## References
- [MITRE T1583.001](https://attack.mitre.org/techniques/T1583/001/)
- [NCSC: Takedowns](https://www.ncsc.gov.uk/section/active-cyber-defence/takedown-service)
