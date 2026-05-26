# Microsoft Defender for Office 365 — Alert & Policy Configuration

## Required MDO Alert Policies (Enable All)
Security & Compliance → Policies & Rules → Alert policies:
- [x] Email forwarding rule created to external domain ← **GEN-CO-001**
- [x] Malware campaign detected after delivery ← **GEN-IA-001**
- [x] Phish campaign detected after delivery ← **GEN-IA-001**
- [x] Suspicious email forwarding activity ← **GEN-CO-001**
- [x] Unusual volume of email reported as phish
- [x] User accessed malicious URL

## Safe Links & Safe Attachments (must be enabled)
- Safe Attachments: Block mode, enable for internal messages
- Safe Links: All URLs rewritten and time-of-click checked
- Zero-hour Auto Purge (ZAP): Enabled for phishing and malware

## Anti-Phishing Policy
Configure impersonation protection for:
- All C-suite executives (CEO, CFO, CISO)
- Financial controllers and AP team members
- IT administrators

## Hunting Queries for SOC Use
```kql
// Find all malicious emails delivered in last 7 days
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryAction == "Delivered" and ThreatTypes != ""
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, ThreatTypes, DeliveryLocation

// Find users who clicked malicious links
UrlClickEvents
| where Timestamp >= ago(7d)
| where ActionType == "ClickAllowed" and ThreatTypes != ""
| project Timestamp, AccountUpn, Url, ThreatTypes
```
