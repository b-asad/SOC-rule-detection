# GEN-IA-002 — Valid Accounts: Impossible Travel

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IA-002` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1078 — Valid Accounts |
| **Sector** | **Generic** — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Cloud Apps |
| **Log Source** | `SigninLogs` (Entra ID) · `AADSignInEventsBeta` (Defender XDR) · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |
| **Review Date** | August 2026 |

---

## Description

Detects successful authentication from two geographically distant locations within a timeframe that is physically impossible to travel between (effective speed > 900 km/h). This is a strong indicator of credential compromise, session token theft via Adversary-in-the-Middle (AiTM) phishing, or stolen access tokens.

This rule is most effective when enriched with your trusted VPN range watchlist. False positives primarily come from corporate VPN egress nodes and cloud proxy services — both should be added to the `TrustedVPNRanges` watchlist during customer onboarding.

Entra ID Protection raises a built-in **Atypical travel** risk event. This rule provides the Sentinel/XDR alert equivalent and adds investigation queries not available natively.

---

## Microsoft Sentinel KQL

```kql
// ───────────────────────────────────────────────────────────────
// GEN-IA-002 | Impossible Travel Detection
// Frequency: 15m | Lookback: 30m | Threshold: > 0
// Entity: Account → UserPrincipalName | IP → IPAddress
// Playbook: PB-REVOKE-SESSION
// ───────────────────────────────────────────────────────────────
let MaxSpeedKmh = 900.0;
let MinDistanceKm = 100.0;
let TrustedRanges = (_GetWatchlist('TrustedVPNRanges') | project SearchKey);
SigninLogs
| where TimeGenerated >= ago(30m)
| where ResultType == "0"
| where IPAddress !in (TrustedRanges)
| where NetworkLocationDetails !contains "trustedNamedLocation"
| extend Lat  = todouble(LocationDetails.geoCoordinates.latitude)
| extend Lon  = todouble(LocationDetails.geoCoordinates.longitude)
| extend City    = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, Lat, Lon, City, Country, AppDisplayName, DeviceDetail, ConditionalAccessStatus
| join kind=inner (
    SigninLogs
    | where TimeGenerated >= ago(30m)
    | where ResultType == "0"
    | extend Lat2    = todouble(LocationDetails.geoCoordinates.latitude)
    | extend Lon2    = todouble(LocationDetails.geoCoordinates.longitude)
    | extend City2   = tostring(LocationDetails.city)
    | extend Country2= tostring(LocationDetails.countryOrRegion)
    | project TimeGenerated2=TimeGenerated, UserPrincipalName, IPAddress2=IPAddress, Lat2, Lon2, City2, Country2
) on UserPrincipalName
| where TimeGenerated != TimeGenerated2
| where IPAddress != IPAddress2
| extend TimeDeltaH = abs(datetime_diff('minute', TimeGenerated, TimeGenerated2)) / 60.0
| extend DistKm = 6371.0 * 2 * asin(sqrt(
    pow(sin((Lat2 - Lat) * pi() / 180 / 2), 2) +
    cos(Lat * pi() / 180) * cos(Lat2 * pi() / 180) *
    pow(sin((Lon2 - Lon) * pi() / 180 / 2), 2)
  ))
| extend SpeedKmh = DistKm / TimeDeltaH
| where SpeedKmh > MaxSpeedKmh
| where DistKm > MinDistanceKm
| distinct
    UserPrincipalName,
    FirstSignInTime    = TimeGenerated,
    FirstIP            = IPAddress,
    FirstCity          = City,
    FirstCountry       = Country,
    SecondSignInTime   = TimeGenerated2,
    SecondIP           = IPAddress2,
    SecondCity         = City2,
    SecondCountry      = Country2,
    DistanceKm         = round(DistKm, 0),
    SpeedKmh           = round(SpeedKmh, 0),
    AppDisplayName,
    ConditionalAccessStatus
| order by SpeedKmh desc
```

**Sentinel Settings:** Frequency `15m` · Lookback `30m` · Threshold `> 0` · Entity: Account → `UserPrincipalName` · IP → `IPAddress` · Playbook: `PB-REVOKE-SESSION`

---

## Defender XDR — Advanced Hunting

```kql
// ───────────────────────────────────────────────────────────────
// GEN-IA-002 | Impossible Travel — Defender XDR
// Run: Every hour | Category: InitialAccess | Severity: High
// Entities: User → AccountUpn
// ───────────────────────────────────────────────────────────────
let MaxSpeedKmh = 900.0;
AADSignInEventsBeta
| where Timestamp >= ago(1h)
| where ErrorCode == 0
| extend Lat  = todouble(parse_json(Location).GeoCoordinates.Latitude)
| extend Lon  = todouble(parse_json(Location).GeoCoordinates.Longitude)
| extend City    = tostring(parse_json(Location).City)
| extend Country = tostring(parse_json(Location).CountryCode)
| project Timestamp, AccountUpn, IPAddress, Lat, Lon, City, Country, Application
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp >= ago(1h)
    | where ErrorCode == 0
    | extend Lat2    = todouble(parse_json(Location).GeoCoordinates.Latitude)
    | extend Lon2    = todouble(parse_json(Location).GeoCoordinates.Longitude)
    | extend City2   = tostring(parse_json(Location).City)
    | extend Country2= tostring(parse_json(Location).CountryCode)
    | project Timestamp2=Timestamp, AccountUpn, IPAddress2=IPAddress, Lat2, Lon2, City2, Country2
) on AccountUpn
| where Timestamp != Timestamp2 and IPAddress != IPAddress2
| extend TimeDeltaH = abs(datetime_diff('minute', Timestamp, Timestamp2)) / 60.0
| extend DistKm = 6371.0 * 2 * asin(sqrt(
    pow(sin((Lat2 - Lat) * pi() / 180 / 2), 2) +
    cos(Lat * pi() / 180) * cos(Lat2 * pi() / 180) *
    pow(sin((Lon2 - Lon) * pi() / 180 / 2), 2)
  ))
| extend SpeedKmh = DistKm / TimeDeltaH
| where SpeedKmh > MaxSpeedKmh and DistKm > 100
| distinct AccountUpn, IPAddress, IPAddress2, City, City2, Country, Country2,
    round(DistKm, 0), round(SpeedKmh, 0), Application
| order by SpeedKmh desc
```

---

## Defender for Cloud Apps — CASB

Enable **Impossible travel** anomaly detection policy in MCAS:
- MCAS portal → Policies → Anomaly detection → **Impossible travel**
- Set sensitivity to Medium initially; tighten to High after 30-day baseline
- Scope to: All users, all apps
- Alert severity: High
- Governance: Suspend user (requires customer pre-approval per contract)

Additionally, configure the MCAS **Activity from infrequent country** policy as a complementary detection.

---

## Investigation Guide

### Step 1 — Context Gathering (0–5 minutes)

1. Note both IP addresses and their geolocations from the alert
2. Submit both IPs to VirusTotal and Shodan — is either a known VPN, proxy, or malicious IP?
3. Check if the user is currently travelling for business:
   - Check HR travel booking system
   - Contact the user's direct manager by phone (not email)
4. Is one of the IPs a known corporate VPN exit node? If yes and not in the `TrustedVPNRanges` watchlist, add it and close the alert.

### Step 2 — Sign-in History Review (5–15 minutes)

```kql
// Full 7-day sign-in history for the affected user
SigninLogs
| where UserPrincipalName == "<UPN_FROM_ALERT>"
| where TimeGenerated >= ago(7d)
| project
    TimeGenerated,
    IPAddress,
    City      = tostring(LocationDetails.city),
    Country   = tostring(LocationDetails.countryOrRegion),
    AppDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    DeviceDetail
| order by TimeGenerated desc
```

Identify the user's normal sign-in pattern: usual location, device, applications. Any deviation warrants deeper investigation.

### Step 3 — MFA and Session Analysis (15–25 minutes)

```kql
// Was MFA completed for both sign-in events?
SigninLogs
| where UserPrincipalName == "<UPN>"
| where TimeGenerated >= ago(24h)
| extend MFAStep   = tostring(AuthenticationDetails[0].authenticationMethod)
| extend MFAResult = tostring(AuthenticationDetails[0].authenticationStepResultDetail)
| extend MFAStatus = tostring(MfaDetail.authMethod)
| project TimeGenerated, IPAddress, MFAStep, MFAResult, MFAStatus, ConditionalAccessStatus, ResultType
| order by TimeGenerated desc
```

**Critical finding:** If MFA was satisfied from **both** locations — this indicates session token theft (AiTM phishing). The attacker relayed the MFA response in real time. Treat as **Critical** and escalate.

### Step 4 — Post-Authentication Activity (25–40 minutes)

```kql
// What did the user (or attacker) do after signing in?
AuditLogs
| where InitiatedBy.user.userPrincipalName == "<UPN>"
| where TimeGenerated >= ago(24h)
| project
    TimeGenerated,
    OperationName,
    Result,
    TargetResources,
    AdditionalDetails
| order by TimeGenerated asc
```

Look for:
- **New inbox forwarding rules** — classic BEC persistence
- **OAuth application consents granted** — attacker installing persistent access
- **Password or MFA method changes** — account lockout attack
- **Mass file downloads from SharePoint/OneDrive** — data exfiltration

### Step 5 — BEC Financial Risk Assessment (40–60 minutes)

```kql
// Check for suspicious emails sent from the account
EmailEvents
| where SenderFromAddress contains "<USERNAME>"
| where Timestamp >= ago(24h)
| where RecipientEmailAddress !contains "<CUSTOMER_DOMAIN>"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId
| order by Timestamp desc
```

For finance team accounts: check for payment instruction changes, invoice submission, or wire transfer requests sent from the compromised account.

---

## Response Actions

**Immediate (P1 — within 15 minutes)**
- [ ] **Revoke all active sessions** — Entra ID portal → Users → [user] → Revoke sessions
- [ ] **Reset password** immediately — do not allow the user to self-service reset
- [ ] **Force MFA re-enrolment** — disable current MFA methods and require re-registration
- [ ] **Block suspicious source IP** — Conditional Access named location → Mark as untrusted
- [ ] **Notify user's manager** by phone — confirm whether the user is genuinely travelling
- [ ] **Open P1 incident ticket** — tag `IMPOSSIBLE-TRAVEL`, `P1`

**Within 1 Hour**
- [ ] **Review OAuth app consents** — revoke any consents granted during the suspicious session
- [ ] **Audit email forwarding rules** — Exchange Online admin → check for new external forwarding
- [ ] **Check SharePoint/OneDrive** for mass file downloads in the last 24 hours
- [ ] **Review all Entra ID changes** made by the account in the last 24 hours
- [ ] **For finance accounts:** check if any payment instructions, wire transfers, or supplier detail changes were initiated

**Recovery**
- [ ] Re-enable Entra ID Continuous Access Evaluation (CAE) for the user
- [ ] Enforce location-based Conditional Access policy restricting sign-ins to approved countries
- [ ] Brief the user on AiTM phishing — token theft can bypass MFA

---

## False Positives

| Scenario | Evidence | Mitigation |
|----------|---------|-----------|
| Corporate VPN exit node in different country | IP resolves to known VPN provider (Zscaler, Palo Alto, Cisco) | Add IP range to `TrustedVPNRanges` Sentinel watchlist + Entra ID Named Location (trusted) |
| Business travel — two devices (office + laptop on VPN) | User has legitimate travel itinerary, both IPs consistent with known locations | Per-user travel suppression — document with manager approval, 14-day maximum |
| Cloud proxy / Zscaler egress with changing exit IPs | All IPs resolve to the same cloud proxy vendor ASN | Add vendor ASN CIDR blocks to trusted named location |
| Split-tunnel VPN — local device + VPN assigned different geo | Consistent pattern for this user type (remote developer) | Per-user exclusion with 30-day review |

---

## Tuning Guidance

- Increase `MaxSpeedKmh` to `1200` if too many FPs from satellite offices with unusual proxy routing
- Add a minimum `TimeDeltaH > 0.5` to avoid triggering on near-simultaneous auth from shared password manager
- Entra ID Protection's built-in risk signal can be used to pre-filter: `| where RiskLevelAggregated != "none"`
- During onboarding, run the query in manual mode with 7-day lookback to identify all FP patterns before enabling

---

## References

- [MITRE T1078](https://attack.mitre.org/techniques/T1078/)
- [Entra ID Protection: Risky sign-ins](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Microsoft: Detect and remediate AiTM phishing](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/defender-for-office-365-aitm-protection)
