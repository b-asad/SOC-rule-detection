# GEN-IA-003 — External Remote Services: Tor / Anonymiser Access

| Field | Value |
|-------|-------|
| Rule ID | GEN-IA-003 |
| Tactic | Initial Access |
| Technique | T1133 — External Remote Services |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Cloud Apps |
| Log Source | `SigninLogs`, `AADSignInEventsBeta`, `CloudAppEvents` |

## Description
Successful authentication to VPN, RDP gateway, or cloud services from a Tor exit node or known anonymiser IP. Attackers use Tor to obscure their origin when using compromised credentials. Legitimate users rarely connect to corporate resources via Tor.

---

## Microsoft Sentinel KQL
```kql
// GEN-IA-003 | Frequency: 5m | Lookback: 5m
let TorNodes = (externaldata(IP:string) [@"https://check.torproject.org/torbulkexitlist"] with (format="txt"));
SigninLogs
| where TimeGenerated >= ago(5m)
| where ResultType == "0"
| where IPAddress in (TorNodes)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, tostring(LocationDetails.city), tostring(LocationDetails.countryOrRegion), DeviceDetail, ConditionalAccessStatus
```
> **Note:** Replace TorNode external data with a customer-maintained Sentinel watchlist `TorExitNodes` if the external URL is not reachable in air-gapped environments.

---

## Defender for Cloud Apps — CASB Policy
- Activity policy: Login from anonymous IP → Alert Severity High → Suspend user session

---

## Investigation Guide

**Step 1:** Confirm IP is a Tor exit node via [check.torproject.org](https://check.torproject.org/exit-address).  
**Step 2:** Identify what the user accessed — email, files, admin panels?  
**Step 3:** Review post-authentication activity for data access or exfiltration.  
**Step 4:** Contact user's manager to confirm if this is expected (almost always is not).

---

## Response Actions
- [ ] Revoke session immediately
- [ ] Block IP at Conditional Access
- [ ] Audit all actions taken during the session
- [ ] Force password reset + MFA re-enrolment

## References
- [MITRE T1133](https://attack.mitre.org/techniques/T1133/)
