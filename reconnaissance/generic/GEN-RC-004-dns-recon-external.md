# GEN-RC-004 — Reconnaissance: External DNS Reconnaissance

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-RC-004` |
| **MITRE Tactic** | Reconnaissance |
| **MITRE Technique** | T1590.002 — Gather Victim Network Information: DNS |
| **Sector** | Generic — All Customers |
| **Severity** | **Low** |
| **Priority** | **P3** |
| **MS Tools** | Sentinel |
| **Log Source** | DNS Server Logs · `DnsEvents` |
| **Created** | May 2026 |

---

## Description

Systematic DNS enumeration of the organisation's domain — zone transfer attempts, rapid subdomain enumeration queries, or MX/TXT/SPF record harvesting from external sources. These indicate an attacker mapping the organisation's external attack surface prior to targeting.

Primarily informational but valuable for threat hunting context — DNS recon often precedes phishing infrastructure setup and external exploitation.

---

## Microsoft Sentinel KQL

```kql
// GEN-RC-004 | Frequency: 1h | Lookback: 1h
DnsEvents
| where TimeGenerated >= ago(1h)
| where SubType == "LookupQuery"
// Zone transfer attempts
| where QueryType in ("AXFR","IXFR") and ResultCode != 0
// Or rapid subdomain enumeration from external IP
| where ClientIP !startswith "10." and ClientIP !startswith "192.168."
| summarize QueryCount=count(), UniqueNames=dcount(Name), SampleNames=make_set(Name,10)
    by ClientIP, bin(TimeGenerated, 5m)
| where QueryCount > 100 or QueryType in ("AXFR","IXFR")
| extend AlertTitle = strcat("DNS Reconnaissance: ", QueryCount, " queries from ", ClientIP)
```

---

## Response Actions
- [ ] Block zone transfers at DNS server configuration
- [ ] Submit recon IP to threat intel for tracking
- [ ] Review exposed DNS records — remove any that reveal internal infrastructure

## References - [MITRE T1590.002](https://attack.mitre.org/techniques/T1590/002/)
