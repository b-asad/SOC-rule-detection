# SEC-EDU-CA-001 — Education: Credential Stuffing Against Student/Staff Portals

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-EDU-CA-001` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1110.004 — Credential Stuffing |
| **Sector** | **Education** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Cloud Apps |
| **Log Source** | `SigninLogs` · `AzureDiagnostics` (WAF) · `CloudAppEvents` (MCAS) |
| **Sector Context** | University/college student portals, VLE logins, library systems, staff email |
| **Created** | May 2026 |

---

## Description

Credential stuffing attacks against education sector login portals using lists of previously breached username/password combinations. Universities are high-value targets due to large cohorts of students with weak password hygiene, publicly listed email addresses, and access to research data, financial aid systems, and student PII. Attack volume spikes before enrolment periods and exam results releases.

Successful account takeovers are used for: grade manipulation, financial aid fraud, identity theft, and as a foothold for ransomware deployment. JISC Cyber Security should be notified of significant attacks.

---

## Microsoft Sentinel KQL

```kql
// SEC-EDU-CA-001 | Frequency: 10m | Lookback: 10m
SigninLogs
| where TimeGenerated >= ago(10m)
| where ResultType != "0"
| where UserPrincipalName has_any (".ac.uk",".edu","university","college","school")
    or AppDisplayName has_any ("Moodle","Blackboard","Canvas","SharePoint","Exchange","Office 365")
| summarize
    FailCount      = count(),
    UniqueAccounts = dcount(UserPrincipalName),
    AccountSample  = make_set(UserPrincipalName, 5),
    UniqueApps     = dcount(AppDisplayName),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated)
    by IPAddress, tostring(LocationDetails.countryOrRegion)
| where FailCount > 50 and UniqueAccounts > 10
| extend SprayRatio = round(todouble(FailCount) / todouble(UniqueAccounts), 1)
| extend AlertTitle = strcat("Education Portal Credential Stuffing — ", UniqueAccounts, " accounts from ", IPAddress)
| extend JISCObligation = "Notify JISC Cyber Security if significant attack confirmed"
| order by UniqueAccounts desc
```

---

## Defender XDR — Advanced Hunting

```kql
// SEC-EDU-CA-001 | Run: Every hour
AADSignInEventsBeta
| where Timestamp >= ago(1h)
| where ErrorCode != 0
| where AccountUpn has_any (".ac.uk",".edu","university","college")
| summarize FailCount=count(), UniqueAccounts=dcount(AccountUpn), FirstSeen=min(Timestamp)
    by IPAddress, Country
| where FailCount > 100 and UniqueAccounts > 15
| order by UniqueAccounts desc
```

---

## Defender for Cloud Apps — WAF Detection

```kql
// Credential stuffing against web-hosted VLE or portal
AzureDiagnostics
| where TimeGenerated >= ago(15m)
| where Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("/login","/signin","/sso","/auth","/account/login","/student-login","/staff-login")
| where httpStatus_i in (401, 403, 429)
| summarize FailCount=count(), UniqueAgents=dcount(userAgent_s)
    by clientIP_s, bin(TimeGenerated, 5m)
| where FailCount > 200
| extend AlertTitle = strcat("Education Portal Login Flood from ", clientIP_s)
```

---

## Defender for Office 365 — Post-Compromise Check

```kql
// Check for suspicious activity from successfully compromised accounts
SigninLogs
| where IPAddress in ("<ATTACKING_IPS_FROM_ALERT>")
| where ResultType == "0"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
    City = tostring(LocationDetails.city)
// Each successful login = compromised student/staff account
```

---

## Investigation Guide

**Step 1 — Confirm stuffing pattern (< 10 min)**
Low failures-per-account ratio + high unique account count = credential stuffing (not brute force).
Submit attacking IPs to AbuseIPDB and Shodan — are they known credential stuffing infrastructure?

**Step 2 — Identify successful logins from attacking IPs (10–20 min)**
Run the MDO post-compromise query above. Every success is a compromised account.

**Step 3 — Compromised account triage (20–40 min)**
For each compromised account:
```kql
AuditLogs
| where InitiatedBy.user.userPrincipalName == "<STUDENT_UPN>"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, OperationName, Result, TargetResources
| order by TimeGenerated asc
```
Look for: grade portal access, financial aid queries, personal detail changes, email forwarding rules.

**Step 4 — Notify affected cohort (40–60 min)**
Prepare list of compromised accounts for the institution's IT team.
If student financial aid system accessed: notify Finance team — potential fraud in progress.

---

## Response Actions

**Immediate**
- [ ] Block attacking IPs at WAF and Conditional Access Named Locations
- [ ] Force password reset for all accounts successfully authenticated from attacking IPs
- [ ] Enable CAPTCHA or step-up authentication on student/staff login portal
- [ ] Notify university/college IT Security team by phone

**Within 1 Hour**
- [ ] Check compromised accounts for financial aid, grade, or personal data access
- [ ] Notify JISC Cyber Security: [www.jisc.ac.uk/cyber-security](https://www.jisc.ac.uk/cyber-security)
- [ ] Enable MFA enforcement for student portal if not already in place
- [ ] Notify affected students/staff to change passwords

**Regulatory**
- [ ] If student personal data accessed: assess ICO notification (UK GDPR Article 33 — 72h)
- [ ] If financial data accessed: notify Finance Director

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Automated learning management system batch sync | Source IP is known LMS integration server — add to exclusions |
| End-of-term login surge from residential IPs | Increase threshold temporarily during known peak periods |

## References
- [MITRE T1110.004](https://attack.mitre.org/techniques/T1110/004/)
- [JISC: Cyber security for education](https://www.jisc.ac.uk/cyber-security)
- [ICO: Reporting data breaches](https://ico.org.uk/for-organisations/report-a-breach/)
