# GEN-DI-002 — Discovery: Active Directory Enumeration

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DI-002` |
| **MITRE Tactic** | Discovery |
| **MITRE Technique** | T1087.002 / T1069.002 — Account Discovery / Domain Groups |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR |
| **Log Source** | `IdentityQueryEvents` (MDI) · `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Rapid LDAP/SAMR queries enumerating AD users, groups, trusts, or domain admins — standard attacker reconnaissance after initial access to identify high-value targets and privilege escalation paths. Tools: BloodHound/SharpHound, PowerView, ldapdomaindump, net.exe, dsquery. MDI provides the best detection via DC-level LDAP telemetry.

---

## Microsoft Sentinel KQL

```kql
// GEN-DI-002 | Frequency: 10m | Lookback: 10m
// Detection A: MDI LDAP enumeration
IdentityQueryEvents
| where TimeGenerated >= ago(10m)
| where QueryType in ("Ldap","Samr")
| where QueryTarget has_any (
    "Domain Admins","Enterprise Admins","Administrators",
    "cn=users","cn=computers","cn=groups","distinguishedName",
    "adminCount=1","ServicePrincipalName","objectClass=user"
)
| summarize QueryCount=count(), UniqueTargets=dcount(QueryTarget)
    by AccountName, DeviceName, bin(TimeGenerated, 5m)
| where QueryCount > 20
| extend AlertTitle = strcat("AD Enumeration: ", QueryCount, " queries by ", AccountName)
```

```kql
// Detection B: net.exe / dsquery AD enumeration commands
DeviceProcessEvents
| where TimeGenerated >= ago(10m)
| where (
    (FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has_any (
        "group /domain","user /domain","accounts /domain","localgroup","domain admins","enterprise admins"
    ))
    or (FileName =~ "dsquery.exe" and ProcessCommandLine has_any ("*","-scope"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any (
        "Get-ADUser","Get-ADGroup","Get-ADDomain","Get-ADForest","Get-ADTrust",
        "net group","BloodHound","SharpHound","PowerView","Invoke-BloodHound"
    ))
    or (ProcessCommandLine has_any ("BloodHound","SharpHound","PowerView","ldapdomaindump"))
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

---

## Defender for Identity — MDI Native Alerts

| MDI Alert | Indicates |
|-----------|---------|
| **Reconnaissance using LDAP queries** | BloodHound/PowerView LDAP sweep |
| **Account enumeration reconnaissance** | SAMR-based account enumeration |
| **User and IP address reconnaissance** | Network-level AD enum |

All three must be configured as High severity in Defender XDR.

---

## Investigation Guide

**Step 1:** Identify the account and device performing enumeration. Is it a standard user account? (Unusual — attackers use compromised accounts.)
**Step 2:** Was BloodHound or SharpHound run? (Check for SharpHound.exe, SharpHound.ps1, BloodHound.exe file events.)
**Step 3:** What attack paths were identified? Look for subsequent privilege escalation attempts.

---

## Response Actions
- [ ] Isolate the enumerating device if malicious tool detected
- [ ] Identify what AD paths were discovered — prioritise protecting those
- [ ] Enable Entra ID Protection and review anomalous access patterns

## References
- [MITRE T1087.002](https://attack.mitre.org/techniques/T1087/002/)
- [MDI: LDAP reconnaissance alert](https://learn.microsoft.com/en-us/defender-for-identity/reconnaissance-discovery-alerts)
