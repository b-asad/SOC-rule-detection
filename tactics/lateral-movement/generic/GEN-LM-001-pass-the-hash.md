# GEN-LM-001 — Lateral Movement: Pass-the-Hash

| Field | Value |
|-------|-------|
| Rule ID | GEN-LM-001 |
| Tactic | Lateral Movement |
| Technique | T1550.002 — Pass the Hash |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Identity · Defender XDR |
| Log Source | `IdentityLogonEvents`, Windows Security Event 4624 |

## Description
NTLM authentication from a source host not previously seen authenticating to the target — anomalous host-to-host auth pair. Pass-the-Hash uses a captured NTLM hash to authenticate without knowing the cleartext password. MDI provides the highest-fidelity detection.

---

## Microsoft Sentinel KQL
```kql
// GEN-LM-001 | Frequency: 15m | Lookback: 15m
// Uses 30-day baseline of normal auth pairs (requires IdentityLogonEvents or Security Event forwarding)
let BaselinePairs = (
    IdentityLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ActionType == "LogonSuccess" and Protocol == "Ntlm"
    | distinct DeviceName, DestinationDeviceName
);
IdentityLogonEvents
| where Timestamp >= ago(15m)
| where ActionType == "LogonSuccess"
| where Protocol == "Ntlm"
| where LogonType == "Network"
| join kind=leftanti BaselinePairs on DeviceName, DestinationDeviceName
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, Protocol, FailureReason
```

---

## Defender for Identity — MDI Alert
MDI natively detects:
- **Pass-the-Hash attack (lateral movement)** — enable in MDI alert settings
- **Suspected overpass-the-hash attack** — Kerberos request from anomalous source

Both alerts surface in Defender XDR incident queue and should be mapped to P1.

---

## Investigation Guide

**Step 1 — Confirm Auth Anomaly (< 10 min)**  
Is the source-to-destination pair genuinely new (not a recently imaged machine)?  
Check asset inventory for the source device — role, owner, OS.

**Step 2 — Credential Origin**
```kql
// What credentials were dumped from the source device?
DeviceEvents
| where DeviceName == "<SOURCE_DEVICE>" | where Timestamp >= ago(24h)
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Step 3 — Destination Actions**
```kql
// What did the attacker do on the destination device?
DeviceProcessEvents | where DeviceName == "<DEST_DEVICE>" | where Timestamp >= ago(2h)
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```

---

## Response Actions
- [ ] Isolate both source and destination devices
- [ ] Reset the abused account's password
- [ ] Search for additional hops from the destination device
- [ ] Enable Credential Guard on both devices post-rebuild

## References
- [MITRE T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [MDI: Pass-the-Hash detection](https://learn.microsoft.com/en-us/defender-for-identity/lateral-movement-alerts)
