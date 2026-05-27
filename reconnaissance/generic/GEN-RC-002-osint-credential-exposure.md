# GEN-RC-002 — Reconnaissance: Credential Exposure via OSINT / Breach Data

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-RC-002` |
| **MITRE Tactic** | Reconnaissance |
| **MITRE Technique** | T1589.001 — Gather Victim Identity Information: Credentials |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | Microsoft Defender Threat Intelligence (MDTI) · `ThreatIntelligenceIndicator` |
| **Created** | May 2026 |

---

## Description

Organisation's credentials or email addresses found in third-party data breach datasets, paste sites, or dark web forums — indicating attacker reconnaissance has located usable credentials for credential stuffing or targeted phishing. Requires Microsoft Defender Threat Intelligence (MDTI) integration or a third-party breach feed connected to Sentinel.

Proactive detection of exposed credentials allows remediation before the attacker uses them.

---

## Microsoft Sentinel KQL

```kql
// GEN-RC-002 | Frequency: 1h | Lookback: 24h
// Requires: MDTI connector OR threat intel feed with breach data
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(24h)
| where Active == true
| where IndicatorType in ("email","url","domain")
| where Tags has_any ("breach","credential","paste","darkweb","haveibeenpwned","combolist")
// Match against internal email domains
| where EmailSenderAddress has_any (_GetWatchlist('InternalEmailDomains') | project SearchKey)
    or DomainName has_any (_GetWatchlist('InternalEmailDomains') | project SearchKey)
| project TimeGenerated, IndicatorType, EmailSenderAddress, DomainName,
    Description, ConfidenceScore, Tags, ExpirationDateTime
| extend AlertTitle = strcat("Credential Exposure: ", EmailSenderAddress, " in breach data")
| order by ConfidenceScore desc
```

---

## Defender for Cloud Apps — MCAS Identity Risk

Enable MCAS identity risk assessment — MCAS checks user accounts against known breach databases and flags high-risk accounts.

---

## Investigation Guide

**Step 1 — Validate the breach data (0–15 min)**
Which breach dataset are the credentials from? What password was exposed?
Have the credentials already been rotated since the breach date?

**Step 2 — Force password reset (15–30 min)**
Reset the password for every account found in breach data — regardless of breach age.
Enable MFA if not already enforced.

**Step 3 — Check for credential stuffing attempts (30–45 min)**
Run GEN-CA-002 (password spray) check against your Sign-in logs using the exposed email addresses as filter.

---

## Response Actions
- [ ] Force password reset for all accounts found in breach data
- [ ] Enable MFA for any affected accounts not already using MFA
- [ ] Check sign-in logs for those accounts for existing compromise signs
- [ ] Register with HaveIBeenPwned domain monitoring for ongoing alerts

## References
- [MITRE T1589.001](https://attack.mitre.org/techniques/T1589/001/)
- [HaveIBeenPwned: Domain search](https://haveibeenpwned.com/DomainSearch)
