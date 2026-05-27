# GEN-LM-005 — Lateral Movement: Pass-the-Ticket (Kerberos Ticket Reuse)

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-LM-005` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | T1550.003 — Use Alternate Authentication Material: Pass the Ticket |
| **Sector** | Generic — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR |
| **Log Source** | `IdentityLogonEvents` (MDI) · Windows Security Event 4769 |
| **Created** | May 2026 |

---

## Description

A Kerberos ticket (TGT or TGS) used from a different device than where it was issued. Attackers extract Kerberos tickets from memory (Mimikatz `sekurlsa::tickets` or `kerberos::ptt`) and import them on another machine to authenticate without credentials. MDI's DC-level sensor provides the most reliable detection.

---

## Microsoft Sentinel KQL

```kql
// GEN-LM-005 | Frequency: 5m | Lookback: 5m
// Kerberos TGS request from IP different to where TGT was issued
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID == 4769  // Kerberos TGS request
| where TicketOptions == "0x40810010"  // Forwardable + renewable — PtT indicator
| where IpAddress != "-"
| join kind=inner (
    SecurityEvent
    | where TimeGenerated >= ago(1h)
    | where EventID == 4768  // TGT request
    | extend TGTIpAddress = IpAddress
    | project Account, TGTIpAddress
) on Account
| where IpAddress != TGTIpAddress
| project TimeGenerated, Computer, Account, IpAddress, TGTIpAddress, ServiceName, TicketOptions
| extend AlertTitle = strcat("Pass-the-Ticket: ", Account, " — ticket from ", TGTIpAddress, " used from ", IpAddress)
```

---

## Defender for Identity — MDI Alert
MDI natively raises: **Pass-the-Ticket attack** — configure as Critical severity.
MDI correlates TGT issuance location with TGS request origin at the DC level.

---

## Response Actions
- [ ] Isolate both devices (origin and pivot)
- [ ] Reset account password — invalidates existing tickets
- [ ] Purge Kerberos tickets on affected hosts: `klist purge`
- [ ] If Golden Ticket suspected: reset KRBTGT password twice

## References
- [MITRE T1550.003](https://attack.mitre.org/techniques/T1550/003/)
- [MDI: Pass-the-Ticket](https://learn.microsoft.com/en-us/defender-for-identity/lateral-movement-alerts)
