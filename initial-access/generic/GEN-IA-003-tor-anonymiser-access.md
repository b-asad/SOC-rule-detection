# GEN-IA-003 — Initial Access: Authentication via Tor / Anonymiser

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IA-003` |
| **MITRE Technique** | T1133 — External Remote Services |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `SigninLogs` · `CloudAppEvents` (MCAS) |

## Description
Successful authentication to a cloud service or VPN from a known Tor exit node or anonymous proxy. Legitimate users almost never connect to corporate resources via Tor. This rule requires the `TorExitNodes` watchlist to be populated during customer onboarding.

## Microsoft Sentinel KQL
```kql
// GEN-IA-003 | Frequency: 5m | Lookback: 5m
let TorNodes = (_GetWatchlist('TorExitNodes') | project SearchKey);
SigninLogs
| where TimeGenerated >= ago(5m)
| where ResultType == "0"
| where IPAddress in (TorNodes)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
    City=tostring(LocationDetails.city), Country=tostring(LocationDetails.countryOrRegion),
    DeviceDetail, ConditionalAccessStatus
| extend AlertTitle = strcat("Tor Login: ", UserPrincipalName, " from ", IPAddress)
```

## Defender for Cloud Apps
Policy: Login from anonymous IP → Alert Severity High.
MCAS natively flags Tor access — ensure this anomaly policy is enabled.

## Investigation Guide
**Step 1:** Verify IP is a Tor exit node via check.torproject.org.
**Step 2:** What did the user access? Email, files, admin portal?
**Step 3:** Review all actions taken during the session — treat as hostile.
**Step 4:** Was MFA satisfied? If yes → possible AiTM or pre-obtained token (treat as Critical).

## Response Actions
- [ ] Revoke session immediately
- [ ] Block IP in Conditional Access Named Locations
- [ ] Reset password and force MFA re-enrolment
- [ ] Audit all actions taken during the Tor session

## References - [MITRE T1133](https://attack.mitre.org/techniques/T1133/)
