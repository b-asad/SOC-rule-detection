# GEN-LM-001 — Lateral Movement: Pass-the-Hash (NTLM Auth Anomaly)

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-LM-001` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | T1550.002 — Use Alternate Authentication Material: Pass the Hash |
| **Sector** | **Generic** — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Identity · Defender for Endpoint |
| **Log Source** | `IdentityLogonEvents` (MDI) · `DeviceLogonEvents` (MDE) · Windows Security Event 4624 |
| **Created** | May 2026 |

---

## Description

Detects NTLM network authentication from a source device to a destination device that has not historically communicated via NTLM in the past 30 days. Pass-the-Hash (PtH) uses a captured NTLM hash to authenticate without knowing the cleartext password — the hash itself acts as a credential.

Defender for Identity provides the highest-fidelity detection for this technique via its DC-level sensor. This Sentinel rule provides an additional detection layer using a 30-day authentication pair baseline and is particularly valuable for customers without MDI deployed.

---

## Microsoft Sentinel KQL

```kql
// GEN-LM-001 | Frequency: 15m | Lookback: 15m | Threshold: > 0
// Requires 30-day baseline of normal NTLM authentication pairs
// Best results after 30 days of data collection in the workspace
let BaselinePairs = (
    IdentityLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ActionType == "LogonSuccess"
    | where Protocol == "Ntlm"
    | where LogonType == "Network"
    | distinct DeviceName, DestinationDeviceName, AccountName
);
IdentityLogonEvents
| where Timestamp >= ago(15m)
| where ActionType == "LogonSuccess"
| where Protocol == "Ntlm"
| where LogonType == "Network"
// Exclude machine account authentication (ends with $)
| where not(AccountName endswith "$")
// Anti-join with baseline — find new host-to-host auth pairs
| join kind=leftanti BaselinePairs on DeviceName, DestinationDeviceName, AccountName
// Exclude known management servers
| where not(DeviceName has_any ("sccm","intune","mgmt","monitor","backup"))
| project
    Timestamp, AccountName, AccountDomain,
    DeviceName, DestinationDeviceName,
    Protocol, LogonType, ActionType, FailureReason
| extend AlertTitle = strcat("Anomalous NTLM Auth: ", DeviceName, " → ", DestinationDeviceName, " as ", AccountName)
| extend Severity = "Critical"
| extend MitreTechnique = "T1550.002"
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-LM-001 | Run: Every hour | Severity: High | Category: LateralMovement
// Uses MDI IdentityLogonEvents
let Baseline = (
    IdentityLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where Protocol == "Ntlm" and ActionType == "LogonSuccess"
    | distinct DeviceName, DestinationDeviceName, AccountName
);
IdentityLogonEvents
| where Timestamp >= ago(1h)
| where ActionType == "LogonSuccess" and Protocol == "Ntlm"
| where not(AccountName endswith "$")
| join kind=leftanti Baseline on DeviceName, DestinationDeviceName, AccountName
| project
    Timestamp, AccountName, DeviceName, DestinationDeviceName,
    Protocol, LogonType
| order by Timestamp desc
```

---

## Defender for Identity — MDI Alerts

MDI independently detects PtH via DC-level Kerberos and NTLM analysis:

| MDI Alert | Maps To | Priority |
|-----------|---------|---------|
| **Pass-the-Hash attack (lateral movement)** | GEN-LM-001 | P1 — auto-merge incident |
| **Suspected overpass-the-hash attack** | GEN-LM-001 variant | P1 |
| **Remote code execution attempt** | Follow-on | P1 |

Ensure MDI alert **Pass-the-Hash** is configured as High severity in Defender XDR alert settings.

---

## Defender for Endpoint — Credential Source Investigation

```kql
// Where did the attacker get the hash? Find credential dumping on source device
DeviceEvents
| where DeviceName == "<SOURCE_DEVICE_FROM_ALERT>"
| where Timestamp between (ago(24h) .. now())
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

```kql
// What did the attacker do on the destination device?
DeviceProcessEvents
| where DeviceName == "<DESTINATION_DEVICE>"
| where Timestamp >= "<AUTH_TIME>"
| where AccountName == "<ACCOUNT_FROM_ALERT>"
| project Timestamp, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Validate the anomaly (< 10 min)**
Is this a genuinely new host pair, or was it recently installed/renamed?
- Check device inventory for both source and destination: age, OS, role, owner
- If the source device was recently onboarded, this may be a baseline gap (not an attack)

**Step 2 — Credential origin (10–25 min)**
Run the LSASS access query on the source device. Was there a recent credential dump (GEN-CA-001)?

**Step 3 — Destination device activity (25–40 min)**
Run the "what did they do" query on the destination device. Did they install services, create accounts, establish C2?

**Step 4 — Expand the hunt (40–60 min)**
```kql
// Find all anomalous NTLM hops in the network — is this one hop or a chain?
IdentityLogonEvents
| where Timestamp >= ago(4h) and Protocol == "Ntlm" and ActionType == "LogonSuccess"
| where AccountName in ("<COMPROMISED_ACCOUNTS>")
| project Timestamp, AccountName, DeviceName, DestinationDeviceName
| order by Timestamp asc
```

---

## Response Actions
**Immediate**
- [ ] Isolate both source and destination devices
- [ ] Reset the abused account's password (and all other accounts dumped from the source device)
- [ ] Purge Kerberos tickets on both devices: `klist purge` via Live Response

**Short-term**
- [ ] Search for further lateral movement hops from the destination device
- [ ] Enable Credential Guard on all affected devices post-rebuild
- [ ] Disable NTLMv1 organisation-wide via Group Policy

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| New workstation — baseline gap | Verify device age in asset inventory; if < 30 days old, this is expected — add to allowlist |
| Recently changed hostname | Same device, different name — add old/new pair to baseline |
| IT admin NTLM to new server | Verify with IT admin; add approved management server pairs to exclusions watchlist |

## References
- [MITRE T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [MDI: PtH detection](https://learn.microsoft.com/en-us/defender-for-identity/lateral-movement-alerts#suspected-identity-theft-pass-the-hash-external-id-2017)
