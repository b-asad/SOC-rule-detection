# SEC-GOV-IA-001 — Government: Nation-State Spearphishing Campaign

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-GOV-IA-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1566.002 — Spearphishing Link |
| **Sector** | **Government** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 · Defender XDR · Defender for Cloud Apps |
| **Log Source** | `EmailEvents` · `EmailUrlInfo` · `UrlClickEvents` (MDO) · `SigninLogs` |
| **Sector Context** | Central government departments, local government, NDPBs, defence contractors, critical national infrastructure |
| **Created** | May 2026 |

---

## Description

Detects spearphishing emails targeting government staff with links to recently registered, low-reputation, or newly seen domains — a primary initial access vector for nation-state threat actors (APT28/Fancy Bear, APT29/Cozy Bear, APT40, Lazarus Group). Government organisations are high-priority targets due to the value of classified or sensitive policy information.

This rule correlates email delivery with URL click events and enriches with domain age intelligence to identify high-confidence spearphishing attempts before a payload is delivered.

**Regulatory:** Government organisations are subject to GovAssure, the NCSC Cyber Assessment Framework (CAF), and must report significant cyber incidents to NCSC via [report.ncsc.gov.uk](https://report.ncsc.gov.uk).

---

## Microsoft Sentinel KQL

```kql
// SEC-GOV-IA-001 | Frequency: 5m | Lookback: 1h | Threshold: > 0
// Requires MDTI (Microsoft Defender Threat Intelligence) for domain age enrichment
// or domain age data in a custom watchlist
let GovernmentDomains = (_GetWatchlist('GovernmentEmailDomains') | project SearchKey);
let NewDomainThreshold = 30; // Flag domains registered in last 30 days
// Find URLs in emails delivered to government staff
EmailUrlInfo
| where TimeGenerated >= ago(1h)
| where Url !has "microsoft.com" and Url !has "office.com" and Url !has "gov.uk"
| join kind=inner (
    EmailEvents
    | where TimeGenerated >= ago(1h)
    | where DeliveryAction != "Blocked"
    | where RecipientEmailAddress has_any (".gov.uk",".mod.uk",".police.uk",".nhs.uk")
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderFromDomain, Subject, ThreatTypes
) on NetworkMessageId
| extend UrlDomain = tostring(parse_url(Url).Host)
// Enrich with TI — flag if domain is in threat intel or newly registered
| join kind=leftouter (
    ThreatIntelligenceIndicator
    | where Active == true and ExpirationDateTime > now()
    | where IndicatorType == "DomainName"
    | project DomainName, ThreatType, Description, ConfidenceScore
) on $left.UrlDomain == $right.DomainName
| where isnotempty(ThreatType) or ThreatTypes != ""
| project
    TimeGenerated, RecipientEmailAddress, SenderFromAddress,
    SenderFromDomain, Subject, Url, UrlDomain,
    ThreatType, ThreatTypes, ConfidenceScore
| extend AlertTitle = strcat("APT-Suspected Phishing to Government Address: ", RecipientEmailAddress)
| extend NCSObligation = "Report to NCSC via report.ncsc.gov.uk if nation-state attribution suspected"
```

---

## Defender for Office 365 — MDO URL Analysis

```kql
// Check if any users clicked the phishing link
UrlClickEvents
| where Timestamp >= ago(24h)
| where Url has_any ("<PHISHING_DOMAIN_FROM_ALERT>")
| project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, IPAddress
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Nation-State Attribution Indicators (< 15 min)**
Submit the phishing domain and email sender to:
- NCSC Suspicious Email Reporting Service (SERS): report@phishing.gov.uk
- Microsoft Defender Threat Intelligence for attribution clues
- VirusTotal graph for infrastructure overlap with known APT campaigns

Look for: lookalike domains mimicking GOV.UK, use of Cloudflare or CDN hosting to obscure origin, DKIM/SPF bypass techniques.

**Step 2 — Scope of Targeting (15–30 min)**
Was this targeted (1–5 recipients = spearphishing) or broad (50+ recipients = phishing campaign)?
Targeted emails to senior officials (Ministers, Permanent Secretaries, senior civil servants) = higher priority, possible espionage motive.

**Step 3 — Payload Analysis (30–60 min)**
If any user clicked: immediately check for credential entry or file download.
Run GEN-IA-001 (Office macro child process) and GEN-IA-002 (impossible travel) on the affected account.

---

## Response Actions
**Immediate**
- [ ] Revoke any sessions from accounts that clicked the link
- [ ] Block the phishing domain in MDO and at DNS level
- [ ] Notify the organisation's IT Security team and Departmental Security Officer (DSO)

**Regulatory**
- [ ] Report to NCSC via [report.ncsc.gov.uk](https://report.ncsc.gov.uk) if nation-state attribution suspected
- [ ] Notify Cabinet Office COBR if sensitive government data may be at risk
- [ ] Complete GovAssure incident report if applicable

## References
- [MITRE T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [NCSC: Spearphishing guidance](https://www.ncsc.gov.uk/collection/phishing-attacks)
- [NCSC: Report a cyber incident](https://report.ncsc.gov.uk)
