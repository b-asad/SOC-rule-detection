# RA-CA-001 — Credential Stuffing: eCommerce / Loyalty Portal

| Field | Value |
|-------|-------|
| Rule ID | RA-CA-001 |
| Tactic | Credential Access |
| Technique | T1110.004 — Credential Stuffing |
| Sector | **Fashion & Apparel Retail** |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Cloud Apps |
| Log Source | Azure WAF / `AzureDiagnostics`, `SigninLogs` (Entra External ID) |
| Retail Context | eCommerce login, loyalty programme portal, DTC brand website |

## Description
Credential stuffing against fashion eCommerce platforms using leaked breach credentials. Fashion retail is heavily targeted due to high-value loyalty points, stored payment methods, and resellable gift cards/vouchers. Indicators: high login failure rate, diverse user agents, distributed source IPs hitting the same login endpoint.

---

## Microsoft Sentinel KQL
```kql
// RA-CA-001 | Frequency: 5m | Lookback: 15m
AzureDiagnostics
| where TimeGenerated >= ago(15m) and Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("/login","/signin","/account/login","/checkout/login","/my-account","/loyalty")
| where httpStatus_i in (401,403,429)
| summarize
    FailCount=count(), UniqueAgents=dcount(userAgent_s), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Sample=any(userAgent_s)
    by clientIP_s
| where FailCount >= 100
| extend AlertTitle = "Credential Stuffing Attack on eCommerce Platform"
| extend BusinessImpact = "Loyalty account takeover, stored card exposure, gift card fraud"
| order by FailCount desc
```

---

## Defender for Cloud Apps — CASB Policy
Enable anomaly policy: **Unusual failed login activity** and **Multiple failed login attempts**.  
Set to alert at 50+ failures from a single IP within 5 minutes.

---

## Investigation Guide

**Step 1 — Confirm Attack Pattern (< 10 min)**  
Single IP vs. distributed (botnet)? Consistent user agent vs. diverse?  
Are requests machine-timed (regular interval) or variable?

**Step 2 — Successful Logins from Attacking IPs**
```kql
AzureDiagnostics | where Category == "ApplicationGatewayAccessLog"
| where clientIP_s in ("<ATTACKING_IPS>") and httpStatus_i == 200
| where requestUri_s has_any ("/login","/signin") | project TimeGenerated, clientIP_s, userAgent_s
```
Any success = compromised account. Immediately force password reset + session revoke.

**Step 3 — Fraudulent Orders from Compromised Accounts**  
Check for gift card orders, voucher purchases, address changes placed immediately after login from attacking IPs.

**Step 4 — Loyalty Points Fraud**  
Review loyalty points redemption from accounts successfully logged in from attacking IPs.

---

## Response Actions
- [ ] Block attacking IPs at WAF
- [ ] Enable/tighten CAPTCHA on login page
- [ ] Force step-up authentication (email OTP) for logins from unknown IPs
- [ ] Reset passwords + revoke sessions for all successfully compromised accounts
- [ ] Hold suspicious orders (gift cards, vouchers, high-value, new address)
- [ ] Freeze loyalty points redemption for compromised accounts
- [ ] Notify customer fraud team and eCommerce manager

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Sale day / product launch — high legitimate traffic | Pre-configure higher thresholds for known high-traffic events |

## References
- [MITRE T1110.004](https://attack.mitre.org/techniques/T1110/004/)
- [OWASP: Credential stuffing prevention](https://owasp.org/www-community/attacks/Credential_stuffing)
