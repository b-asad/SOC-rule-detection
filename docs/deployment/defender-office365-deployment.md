# Microsoft Defender for Office 365 — Configuration Guide

## Alert Policies — Enable Before Deploying Email Rules

Security & Compliance → Policies & Rules → Alert policies — enable all:

| Alert Policy | Maps To | Priority |
|-------------|---------|---------|
| Email forwarding rule created to external domain | GEN-CO-001 | P1 |
| Suspicious email forwarding activity | GEN-CO-001 | P1 |
| Malware campaign detected after delivery | GEN-IA-001 | P1 |
| Phish campaign detected after delivery | GEN-IA-001, SEC-GOV-IA-001 | P1 |
| User accessed malicious URL | SEC-EDU-IA-001, SEC-GOV-IA-001 | P1 |
| Messages have been delayed | GEN-CO-001 variant | P2 |
| Unusual volume of email reported as phish | GEN-CA-002 precursor | P2 |

---

## Safe Links and Safe Attachments — Verify in Block Mode

- **Safe Attachments:** Block mode, enable for internal messages and SharePoint/OneDrive
- **Safe Links:** All URLs rewritten, time-of-click verification enabled, track user clicks enabled
- **Zero-hour Auto Purge (ZAP):** Enabled for phishing and malware — removes delivered malicious emails retroactively

---

## Anti-Phishing Policy — Impersonation Protection

Configure impersonation protection for high-value accounts:
- All C-suite executives (CEO, CFO, CISO, CTO)
- Finance controllers and accounts payable team
- IT administrators
- For Government customers: Ministers, Permanent Secretaries, Director Generals
- For Healthcare customers: CEO, Medical Director, CCIO, Caldicott Guardian

---

## Threat Explorer — Analyst Hunting Queries

Bookmark these searches for frequent use:

```
# All delivered malicious emails last 7 days
EmailEvents | where Timestamp >= ago(7d) | where ThreatTypes != "" | where DeliveryAction == "Delivered"

# All URL clicks on malicious links
UrlClickEvents | where Timestamp >= ago(7d) | where ThreatTypes != "" | where ActionType == "ClickAllowed"

# External forwarding rules created
OfficeActivity | where TimeGenerated >= ago(30d) | where Operation == "New-InboxRule" | where Parameters has "ForwardTo"
```
