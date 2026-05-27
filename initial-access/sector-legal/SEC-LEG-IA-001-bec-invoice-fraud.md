# SEC-LEG-IA-001 — Legal: BEC Invoice Fraud / Conveyancing Fraud

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-LEG-IA-001` |
| **MITRE Technique** | T1657 — Financial Theft |
| **Sector** | Legal |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 |
| **Log Source** | `EmailEvents` · `OfficeActivity` |
| **Sector Context** | Law firms, conveyancers, property solicitors, trust accounts |

## Description
BEC targeting law firm client account transactions — particularly conveyancing fraud (redirecting property purchase funds) and invoice fraud (redirecting client payments). Law firms handle large client account transactions; a single successful BEC can involve millions of pounds. The SRA requires firms to have controls preventing this.

## Microsoft Sentinel KQL
```kql
// SEC-LEG-IA-001 | Frequency: 5m | Lookback: 5m
let LegalBECKeywords = dynamic(["bank details","sort code","account number","payment","please transfer","client account","completion","conveyancing","exchange","invoice","wire transfer","change of bank"]);
EmailEvents
| where TimeGenerated >= ago(5m) and DeliveryAction != "Blocked"
| where Subject has_any (LegalBECKeywords)
| where not(SenderFromDomain has_any (_GetWatchlist('InternalEmailDomains') | project SearchKey))
| project TimeGenerated, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, ThreatTypes
| extend AlertTitle = strcat("BEC/Conveyancing Fraud Risk: ", Subject)
| extend SRAObligation = "SRA: Notify if client money at risk. LSAG Cyber Security toolkit."
```

## Investigation Guide
**Step 1 (Immediate):** Call the accounts/finance team — has any client money been moved based on this email?
**Step 2:** If funds transferred: contact bank fraud team IMMEDIATELY — conveyancing fraud reversal window is very narrow.
**Step 3:** Verify the email domain character-by-character — lookalike domains are common.

## Response Actions
- [ ] Contact client accounts team by phone — freeze any pending transactions
- [ ] If funds transferred: bank fraud team + Action Fraud immediately
- [ ] Block sender domain in MDO
- [ ] Notify COLP, COFA, and SRA if client money at risk

## References
- [MITRE T1657](https://attack.mitre.org/techniques/T1657/) | [SRA: Cybercrime](https://www.sra.org.uk/solicitors/resources/cybercrime/)
