# GEN-RD-002 — Resource Development: Compromised Infrastructure Used Against Tenant

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-RD-002` |
| **MITRE Tactic** | Resource Development |
| **MITRE Technique** | T1584 — Compromise Infrastructure |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel |
| **Log Source** | `ThreatIntelligenceIndicator` · `SigninLogs` · `EmailEvents` |
| **Created** | May 2026 |

---

## Description

Authentication attempts or email delivery from IPs flagged in threat intelligence as compromised infrastructure — attacker-controlled hosts, bullet-proof hosting, compromised legitimate servers, or known APT C2 infrastructure. Attackers often use compromised third-party servers to route their attacks, making blocking their primary infrastructure ineffective without TI.

---

## Microsoft Sentinel KQL

```kql
// GEN-RD-002 | Frequency: 15m | Lookback: 1h
// Match sign-in attempts against threat intel IOCs
let TIIndicators = (
    ThreatIntelligenceIndicator
    | where Active == true and ExpirationDateTime > now()
    | where IndicatorType in ("ipv4-addr","ipv6-addr")
    | where ConfidenceScore >= 70
    | project TI_IP = NetworkIP, ThreatType, Description, ConfidenceScore
);
SigninLogs
| where TimeGenerated >= ago(1h)
| join kind=inner TIIndicators on $left.IPAddress == $right.TI_IP
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName,
    ThreatType, Description, ConfidenceScore
| extend AlertTitle = strcat("TI Match: Sign-in from compromised infra ", IPAddress)
| order by ConfidenceScore desc
```

---

## Response Actions
- [ ] Block the TI-matched IP in Conditional Access
- [ ] If sign-in was successful: treat as GEN-IA-002 (credential compromise) — revoke and reset
- [ ] Report TI matches to your threat intelligence team for attribution

## References - [MITRE T1584](https://attack.mitre.org/techniques/T1584/)
