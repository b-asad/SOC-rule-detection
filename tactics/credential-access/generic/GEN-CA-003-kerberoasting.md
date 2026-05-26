# GEN-CA-003 — Kerberoasting: TGS-REQ Mass Request

| Field | Value |
|-------|-------|
| Rule ID | GEN-CA-003 |
| Tactic | Credential Access |
| Technique | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Identity · Defender XDR |
| Log Source | `IdentityQueryEvents`, Windows Security Event 4769 |

## Description
Mass Kerberos TGS ticket requests for service accounts using RC4 encryption (0x17). Attackers request service tickets offline to crack the service account's NTLM hash. MDI detects this natively; Sentinel provides corroborating telemetry.

---

## Microsoft Sentinel KQL
```kql
// GEN-CA-003 | Frequency: 5m | Lookback: 5m
// Requires Windows Security Event forwarding from DCs
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4-HMAC — weak, targeted by Kerberoasting
| where ServiceName !endswith "$"        // Exclude machine accounts
| summarize
    RequestCount = count(),
    UniqueServices = dcount(ServiceName),
    ServiceList = make_set(ServiceName, 10)
    by Account, IpAddress, bin(TimeGenerated, 1m)
| where RequestCount > 5
| order by RequestCount desc
```

---

## Defender for Identity — MDI Alert
MDI natively raises: **Suspected Kerberos SPN exposure (Kerberoasting)**  
Ensure this alert is mapped to P1 in your Defender XDR alert severity configuration.

---

## Defender XDR — Advanced Hunting
```kql
// GEN-CA-003 | Run: Every hour
IdentityQueryEvents
| where Timestamp >= ago(1h)
| where QueryType == "Kerberoasting"
| project Timestamp, AccountName, DeviceName, QueryTarget, Protocol
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1 — Identify Requester (< 10 min)**  
Which account and device made the TGS requests? Is it a workstation or server? Is the account a service account or user account?

**Step 2 — Services Targeted**  
Which SPNs were requested? Prioritise: `MSSQLSvc`, `HTTP`, `cifs` — these typically belong to powerful service accounts.

**Step 3 — Account Privilege Review**  
For each targeted SPN, check the associated account's group memberships. If Domain Admin or highly privileged: treat as Critical.

**Step 4 — Lateral Movement Post-Crack**  
```kql
IdentityLogonEvents | where AccountName in ("<SERVICE_ACCOUNTS>") | where Timestamp >= ago(24h)
| project Timestamp, DeviceName, DestinationDeviceName, ActionType, Protocol
```

---

## Response Actions
- [ ] **Reset passwords** for all targeted service accounts (long, random passwords ≥ 30 chars)
- [ ] **Convert service accounts** to Group Managed Service Accounts (gMSA) — auto-rotating passwords
- [ ] **Remove unnecessary SPNs** from high-privilege accounts
- [ ] **Disable RC4** Kerberos encryption via GPO — enforce AES only
- [ ] **Investigate requester account** for further compromise indicators

## References
- [MITRE T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [MDI: Kerberoasting alert](https://learn.microsoft.com/en-us/defender-for-identity/compromised-credentials-alerts#suspected-kerberos-spn-exposure-external-id-2410)
