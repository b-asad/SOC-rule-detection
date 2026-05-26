# GEN-IA-002 — Valid Accounts: Impossible Travel

| Field | Value |
|-------|-------|
| Rule ID | GEN-IA-002 |
| Tactic | Initial Access |
| Technique | T1078 — Valid Accounts |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Cloud Apps |
| Log Source | `SigninLogs` (Entra ID), `AADSignInEventsBeta` (Defender XDR) |

## Description
User authenticates successfully from two geographically distant locations within a timeframe physically impossible to travel between (speed > 900 km/h). Strong indicator of credential compromise, session theft, or AiTM phishing.

---

## Microsoft Sentinel KQL
```kql
// GEN-IA-002 | Frequency: 15m | Lookback: 30m
let MaxSpeed = 900.0;
let Exclusions = (_GetWatchlist('TrustedVPNRanges') | project SearchKey);
SigninLogs
| where TimeGenerated >= ago(30m)
| where ResultType == "0"
| where IPAddress !in (Exclusions)
| extend Lat = todouble(LocationDetails.geoCoordinates.latitude)
| extend Lon = todouble(LocationDetails.geoCoordinates.longitude)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, Lat, Lon, City, Country, AppDisplayName
| join kind=inner (
    SigninLogs | where TimeGenerated >= ago(30m) | where ResultType == "0"
    | extend Lat2=todouble(LocationDetails.geoCoordinates.latitude), Lon2=todouble(LocationDetails.geoCoordinates.longitude)
    | extend City2=tostring(LocationDetails.city), Country2=tostring(LocationDetails.countryOrRegion)
    | project TimeGenerated2=TimeGenerated, UserPrincipalName, IPAddress2=IPAddress, Lat2, Lon2, City2, Country2
) on UserPrincipalName
| where TimeGenerated != TimeGenerated2 and IPAddress != IPAddress2
| extend TimeDeltaH = abs(datetime_diff('minute',TimeGenerated,TimeGenerated2))/60.0
| extend DistKm = 6371.0*2*asin(sqrt(pow(sin((Lat2-Lat)*pi()/180/2),2)+cos(Lat*pi()/180)*cos(Lat2*pi()/180)*pow(sin((Lon2-Lon)*pi()/180/2),2)))
| extend SpeedKmh = DistKm/TimeDeltaH
| where SpeedKmh > MaxSpeed and DistKm > 100
| distinct UserPrincipalName, City, City2, Country, Country2, round(DistKm,0), round(SpeedKmh,0), IPAddress, IPAddress2
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-IA-002 | Run: Every hour
let MaxSpeed = 900.0;
AADSignInEventsBeta
| where Timestamp >= ago(1h) and ErrorCode == 0
| extend Lat=todouble(parse_json(Location).GeoCoordinates.Latitude), Lon=todouble(parse_json(Location).GeoCoordinates.Longitude)
| extend City=tostring(parse_json(Location).City), Country=tostring(parse_json(Location).CountryCode)
| project Timestamp, AccountUpn, IPAddress, Lat, Lon, City, Country
| join kind=inner (
    AADSignInEventsBeta | where Timestamp >= ago(1h) and ErrorCode == 0
    | extend Lat2=todouble(parse_json(Location).GeoCoordinates.Latitude), Lon2=todouble(parse_json(Location).GeoCoordinates.Longitude)
    | extend City2=tostring(parse_json(Location).City), Country2=tostring(parse_json(Location).CountryCode)
    | project Timestamp2=Timestamp, AccountUpn, IPAddress2=IPAddress, Lat2, Lon2, City2, Country2
) on AccountUpn
| where Timestamp != Timestamp2 and IPAddress != IPAddress2
| extend TimeDeltaH=abs(datetime_diff('minute',Timestamp,Timestamp2))/60.0
| extend DistKm=6371.0*2*asin(sqrt(pow(sin((Lat2-Lat)*pi()/180/2),2)+cos(Lat*pi()/180)*cos(Lat2*pi()/180)*pow(sin((Lon2-Lon)*pi()/180/2),2)))
| extend SpeedKmh=DistKm/TimeDeltaH
| where SpeedKmh > MaxSpeed and DistKm > 100
| distinct AccountUpn, City, City2, Country, Country2, round(DistKm,0), round(SpeedKmh,0)
```

---

## Defender for Cloud Apps — CASB Policy
Configure in Defender for Cloud Apps → Policies → Create policy → Activity policy:
- **Filter:** Activity = "Login" AND Risk score > 7 AND Activity = "Impossible travel"
- **Alert:** Severity High, notify SOC team
- **Action:** Suspend user (optional, requires pre-approval from customer)

---

## Investigation Guide

**Step 1 — Context (< 5 min)**
- Identify both IPs on VirusTotal and Shodan.
- Check if user is on business travel (HR system / manager contact).
- Is one IP a known corporate VPN? If not already in watchlist, consider adding.

**Step 2 — Sign-in History (5–15 min)**
```kql
SigninLogs | where UserPrincipalName == "<UPN>" | where TimeGenerated >= ago(7d)
| project TimeGenerated, IPAddress, tostring(LocationDetails.city), AppDisplayName, ResultType, tostring(AuthenticationDetails)
| order by TimeGenerated desc
```

**Step 3 — MFA Assessment (15–20 min)**
```kql
SigninLogs | where UserPrincipalName == "<UPN>" | where TimeGenerated >= ago(24h)
| extend MFA = tostring(AuthenticationDetails[0].authenticationStepResultDetail)
| project TimeGenerated, IPAddress, MFA, ConditionalAccessStatus, ResultType
```
If MFA was satisfied from both locations → likely session/cookie theft (AiTM). Treat as Critical.

**Step 4 — Post-Auth Activity (20–35 min)**
```kql
AuditLogs | where InitiatedBy.user.userPrincipalName == "<UPN>" | where TimeGenerated >= ago(24h)
| project TimeGenerated, OperationName, Result, TargetResources | order by TimeGenerated desc
```
Look for: new forwarding rules, OAuth consents, password changes, MFA method changes, bulk downloads.

---

## Response Actions
- [ ] **Revoke all sessions** — Entra ID portal
- [ ] **Reset password** + force MFA re-enrolment
- [ ] **Block suspicious IP** — Conditional Access named location
- [ ] **Audit OAuth app consents** — revoke any unauthorised grants
- [ ] **Check forwarding rules** — Exchange Online
- [ ] **SharePoint/OneDrive bulk download audit** — last 24h

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Corporate VPN exit nodes | Add to TrustedVPNRanges watchlist |
| Zscaler / proxy egress IPs | Add to watchlist; tag as trusted named location in Entra ID |

## References
- [MITRE T1078](https://attack.mitre.org/techniques/T1078/)
- [Entra ID Protection: Risky sign-ins](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
