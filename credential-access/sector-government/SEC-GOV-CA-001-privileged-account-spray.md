# SEC-GOV-CA-001 — Government: Password Spray Against Privileged Civil Servant Accounts

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-GOV-CA-001` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1110.003 — Password Spraying |
| **Sector** | **Government** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR · Defender for Cloud Apps |
| **Log Source** | `SigninLogs` · `IdentityLogonEvents` (MDI) |
| **Sector Context** | Central government, FCDO, MoD, Cabinet Office, intelligence-adjacent departments |
| **Created** | May 2026 |

---

## Description

Password spray attacks specifically targeting privileged government accounts — Senior Civil Servants (SCS), ministerial private offices, Head of Department accounts, and IT administrator accounts. Nation-state actors routinely use spray attacks as a low-noise initial access technique against government organisations before pivoting to classified systems.

A single compromised SCS or ministerial account gives an attacker access to policy documents, cabinet briefings, and sensitive official correspondence. NCSC should be notified for spray attacks against government organisations, particularly if nation-state attribution is suspected.

---

## Microsoft Sentinel KQL

```kql
// SEC-GOV-CA-001 | Frequency: 10m | Lookback: 10m
let PrivGovAccounts = (_GetWatchlist('PrivilegedGovAccounts') | project SearchKey);
let TrustedRanges  = (_GetWatchlist('TrustedVPNRanges') | project SearchKey);
// Detection 1: Spray against known privileged accounts
let PrivilegedSpray = (
    SigninLogs
    | where TimeGenerated >= ago(10m)
    | where ResultType != "0"
    | where IPAddress !in (TrustedRanges)
    | where UserPrincipalName in~ (PrivGovAccounts)
        or UserPrincipalName has_any (
            "scs","scs-","minister","ps-","private-office","permanent",
            "director-general","dg-","spad-","cabinet-office","security-"
        )
    | summarize FailCount=count(), UniqueAccounts=dcount(UserPrincipalName),
        AccountSample=make_set(UserPrincipalName,5)
        by IPAddress, tostring(LocationDetails.countryOrRegion)
    | where FailCount > 5
    | extend DetectionType = "PrivilegedAccountSpray"
);
// Detection 2: Broad spray across the organisation from single IP
let BroadSpray = (
    SigninLogs
    | where TimeGenerated >= ago(10m)
    | where ResultType != "0"
    | where IPAddress !in (TrustedRanges)
    | summarize FailCount=count(), UniqueAccounts=dcount(UserPrincipalName)
        by IPAddress, tostring(LocationDetails.countryOrRegion)
    | where FailCount > 30 and UniqueAccounts > 8
    | extend DetectionType = "BroadOrganisationSpray"
);
PrivilegedSpray | union BroadSpray
| extend AlertTitle = strcat("Gov Credential Spray from ", IPAddress)
| extend NationStateNote = "Nation-state actors (APT28, APT29, APT40) commonly use spray against government — notify NCSC"
| extend NCSObligation = "Report to NCSC via report.ncsc.gov.uk — government credential spray"
```

---

## Defender for Identity — MDI Native Detection

MDI provides native spray detection via Kerberos (Event 4771) and NTLM (Event 4776) at the DC level:
- Alert: **Password spray attack (Kerberos)**
- Alert: **Password spray attack (LDAP)**

Configure these alerts as **Critical severity** in Defender XDR for government sector customers.

---

## Defender XDR — Advanced Hunting

```kql
// SEC-GOV-CA-001 | Run: Every hour
let TrustedRanges = (_GetWatchlist('TrustedVPNRanges') | project SearchKey);
AADSignInEventsBeta
| where Timestamp >= ago(1h)
| where ErrorCode != 0
| where IPAddress !in (TrustedRanges)
| summarize FailCount=count(), UniqueAccounts=dcount(AccountUpn), FirstSeen=min(Timestamp)
    by IPAddress, Country
| where FailCount > 20 and UniqueAccounts > 5
| order by UniqueAccounts desc
```

---

## Defender for Cloud Apps — MCAS

Enable anomaly policy: **Multiple failed login attempts** — set sensitivity: High for government tenants.
Enable: **Activity from infrequent country** — government users should have very limited approved geographies.

---

## Investigation Guide

**Step 1 — Confirm spray pattern (0–10 min)**
Check the attacks-per-account ratio. True spray = < 3 attempts per account. Submit attacking IP to Shodan — is it a VPS, bulletproof hosting, or residential IP?

**Step 2 — Check for successful logins (10–20 min)**
```kql
SigninLogs
| where IPAddress == "<ATTACKING_IP>"
| where ResultType == "0"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, UserPrincipalName, AppDisplayName, ConditionalAccessStatus
```
Any success = compromised government account. Escalate to P1 immediately.

**Step 3 — Nation-state attribution indicators (20–40 min)**
Is the attack:
- From a TOR exit node? → High confidence nation-state or criminal
- From a known APT infrastructure IP (check NCSC threat intel)? → Nation-state
- From a bulletproof hosting provider? → Criminal or nation-state
- Time-zone consistent with a specific nation-state working day? → Attribution clue

Submit IOCs to NCSC for enrichment.

**Step 4 — Scope the blast radius (40–60 min)**
Search the same IPs across all other government department tenants if the MSSP serves multiple departments.

---

## Response Actions

**Immediate**
- [ ] Block attacking IPs in Conditional Access Named Locations
- [ ] Reset passwords for any successfully authenticated accounts
- [ ] Enforce MFA for all targeted accounts if not already in place
- [ ] Notify Departmental Security Officer (DSO)

**Within 1 Hour**
- [ ] Report to NCSC: [report.ncsc.gov.uk](https://report.ncsc.gov.uk)
- [ ] Share IOCs (attacking IPs, timing, targeted accounts) with NCSC
- [ ] Brief SIRO and Head of Cyber Security

**Regulatory**
- [ ] GovAssure: Document incident for assurance review
- [ ] NCSC CAF: Record under CAF Objective A — Managing Security Risk

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Misconfigured departmental service account using wrong password | Single account, not spray pattern — rule threshold of 5+ accounts won't trigger |
| Remote access system login page being scanned (not credential spray) | Distinguish by error code — 401 (auth failure) vs 400 (bad request from scanner) |

## References
- [MITRE T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- [NCSC: Password spray defence](https://www.ncsc.gov.uk/guidance/spray-attacks-defence)
- [NCSC: Report an incident](https://report.ncsc.gov.uk)
