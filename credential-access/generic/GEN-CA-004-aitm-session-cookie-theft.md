# GEN-CA-004 — Credential Access: AiTM / Session Cookie Theft

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CA-004` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1539 — Steal Web Session Cookie |
| **Sector** | Generic — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender XDR |
| **Log Source** | `SigninLogs` · `AuditLogs` · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |

---

## Description

Adversary-in-the-Middle (AiTM) phishing proxies relay authentication in real time, capturing session cookies that bypass MFA entirely. The attacker then uses the stolen session token directly from a different IP address. Indicators: successful MFA sign-in immediately followed by successful authentication from a different IP without MFA, anomalous session token reuse, and post-authentication activity from unexpected locations.

Evilginx2, Modlishka, Muraena, and the Microsoft-documented "large-scale AiTM campaign" toolkits all produce this signature.

---

## Microsoft Sentinel KQL

```kql
// GEN-CA-004 | Frequency: 5m | Lookback: 1h
// AiTM signature: MFA success from IP-A, then immediate activity from IP-B without MFA
let TrustedRanges = (_GetWatchlist('TrustedVPNRanges') | project SearchKey);
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType == "0"
| where IPAddress !in (TrustedRanges)
// Find sessions where MFA was completed
| extend MFACompleted = tostring(AuthenticationRequirement) == "multiFactorAuthentication"
| where MFACompleted
| extend Lat  = todouble(LocationDetails.geoCoordinates.latitude)
| extend Lon  = todouble(LocationDetails.geoCoordinates.longitude)
| extend City = tostring(LocationDetails.city)
| project TimeGenerated, UserPrincipalName, IPAddress, Lat, Lon, City, AppDisplayName, SessionId
// Self-join to find same user from different IP within 30 minutes
| join kind=inner (
    SigninLogs
    | where TimeGenerated >= ago(1h) and ResultType == "0"
    | where IPAddress !in (TrustedRanges)
    | extend MFACompleted2 = tostring(AuthenticationRequirement)
    | extend Lat2  = todouble(LocationDetails.geoCoordinates.latitude)
    | extend Lon2  = todouble(LocationDetails.geoCoordinates.longitude)
    | extend City2 = tostring(LocationDetails.city)
    | project TimeGenerated2=TimeGenerated, UserPrincipalName, IPAddress2=IPAddress, Lat2, Lon2, City2, AppDisplayName2=AppDisplayName, MFACompleted2
) on UserPrincipalName
| where TimeGenerated != TimeGenerated2 and IPAddress != IPAddress2
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated2)) <= 30
// MFA from first IP, then no MFA from second IP = stolen session
| where MFACompleted and MFACompleted2 == "singleFactorAuthentication"
| extend DistKm = round(6371.0 * 2 * asin(sqrt(pow(sin((Lat2-Lat)*pi()/360),2)+cos(Lat*pi()/180)*cos(Lat2*pi()/180)*pow(sin((Lon2-Lon)*pi()/360),2))),0)
| where DistKm > 50
| distinct UserPrincipalName, IPAddress, IPAddress2, City, City2, DistKm, AppDisplayName
| extend AlertTitle = strcat("AiTM Suspected: ", UserPrincipalName, " — session reused from ", City2)
| extend Severity = "Critical"
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-CA-004 | Run: Every hour — Session token used from new IP without MFA
AADSignInEventsBeta
| where Timestamp >= ago(1h) and ErrorCode == 0
| where AuthenticationRequirement == "singleFactorAuthentication"  // No MFA
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp >= ago(2h) and ErrorCode == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"  // Prior MFA
    | project AccountUpn, PreviousIP=IPAddress, PreviousMFATime=Timestamp
) on AccountUpn
| where IPAddress != PreviousIP
| where Timestamp > PreviousMFATime
| where datetime_diff('minute', Timestamp, PreviousMFATime) <= 60
| project Timestamp, AccountUpn, IPAddress, PreviousIP, PreviousMFATime, Application
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1 — Confirm AiTM vs legitimate (0–5 min)**
Is `IPAddress2` a known corporate VPN? If not: confirm it's not a known location for this user.
Look at the AppDisplayName — what application was the session used for? Email and cloud storage = highest risk.

**Step 2 — Post-theft activity (5–20 min)**
```kql
AuditLogs | where InitiatedBy.user.userPrincipalName == "<UPN>"
| where TimeGenerated between ("<THEFT_TIME>" .. now())
| project TimeGenerated, OperationName, Result, TargetResources | order by TimeGenerated asc
```
AiTM post-compromise actions: inbox forwarding rules, OAuth consent grants, bulk email access, SharePoint downloads.

**Step 3 — Revoke immediately (20–25 min)**
Revoke sessions, reset password, force MFA re-enrolment, audit all actions in the stolen session.

---

## Response Actions
- [ ] Revoke ALL active sessions — Entra ID
- [ ] Reset password + force MFA re-enrolment
- [ ] Review and delete any inbox forwarding rules created
- [ ] Review and revoke any OAuth app consents granted
- [ ] Deploy or verify: Conditional Access policy requiring compliant device AND location-based restrictions

## References
- [MITRE T1539](https://attack.mitre.org/techniques/T1539/)
- [Microsoft: Defend against AiTM](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/defender-for-office-365-aitm-protection)
