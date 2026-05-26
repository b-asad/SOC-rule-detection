# RA-IM-001 — Brand Account Takeover: Social Media / Influencer Account Compromise

| Field | Value |
|-------|-------|
| Rule ID | RA-IM-001 |
| Tactic | Impact |
| Technique | T1531 — Account Access Removal / T1491 — Defacement |
| Sector | **Fashion & Apparel Retail** |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Cloud Apps |
| Log Source | `CloudAppEvents`, `SigninLogs`, CASB social media monitoring |
| Retail Context | Brand social media accounts, influencer partner accounts, DTC brand communications |

## Description
Compromise of a fashion brand's social media or influencer partner account — used for scam posts, counterfeit product promotion, or brand defamation. Fashion brands face heightened social media attack risk due to large follower counts and high-value brand equity. Account takeover is typically preceded by credential phishing targeting the social media manager.

---

## Microsoft Sentinel KQL
```kql
// RA-IM-001 | Frequency: 15m | Lookback: 1h
// Detects Entra ID / O365 account compromise for brand social media managers
let SocialMediaRoles = (_GetWatchlist('SocialMediaManagers') | project SearchKey);
SigninLogs
| where TimeGenerated >= ago(1h) and ResultType == "0"
| where UserPrincipalName in (SocialMediaRoles)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend IsUnexpectedGeo = (Country !in (dynamic(["GB","US","FR","IT"])))  // Adjust per customer
| extend IsSuspiciousIP = (NetworkLocationDetails !contains "trustedNamedLocation")
| where IsUnexpectedGeo or IsSuspiciousIP
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName, IsUnexpectedGeo, DeviceDetail
```

---

## Defender for Cloud Apps — CASB OAuth App Monitoring
Monitor for OAuth consent to social media management apps from unexpected accounts:
```kql
CloudAppEvents
| where TimeGenerated >= ago(1h)
| where ActionType == "OAuthApplicationConsent"
| where Application has_any ("Instagram","Twitter","TikTok","LinkedIn","Hootsuite","Sprout","Buffer")
| where AccountDisplayName in (dynamic(["<BRAND_SOCIAL_ACCOUNTS>"]))
| project TimeGenerated, AccountDisplayName, Application, IPAddress, CountryCode
```

---

## Investigation Guide

**Step 1 — Confirm Account Status (< 10 min)**  
Check if the brand's social media account is still under control.  
Has any content been posted that is inconsistent with brand guidelines?

**Step 2 — Session Revocation**  
Work with the customer's social media team to:
- Log out all other sessions on the social platform
- Change password and enable 2FA
- Revoke all connected third-party app OAuth tokens

**Step 3 — Brand Reputation Assessment**  
Has any malicious content been posted? Screenshot and preserve evidence.  
Prepare customer communications response if harmful content was published.

---

## Response Actions
- [ ] Revoke all active Entra ID sessions for affected account
- [ ] Reset password + force MFA re-enrolment
- [ ] Work with social media team to remove any harmful posts
- [ ] Notify brand/comms team for crisis communications readiness
- [ ] Report to social platform's trust & safety team for account recovery assistance
- [ ] Preserve evidence of any malicious posts for legal action

## References
- [MITRE T1531](https://attack.mitre.org/techniques/T1531/)
- [UK IPO: Brand protection](https://www.gov.uk/topic/intellectual-property/trade-marks)
