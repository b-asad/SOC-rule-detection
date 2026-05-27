# SEC-GOV-LM-001 — Government: Lateral Movement Toward Restricted/Classified Systems

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-GOV-LM-001` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | T1021 — Remote Services |
| **Sector** | **Government** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR · Defender for Endpoint |
| **Log Source** | `IdentityLogonEvents` (MDI) · `DeviceLogonEvents` (MDE) · Firewall logs |
| **Sector Context** | Government departments, FCDO, MoD, intelligence-adjacent organisations, national security systems |
| **Created** | May 2026 |

---

## Description

Authentication from a standard IT host toward hosts tagged as restricted, classified, or sensitive government systems — indicating a potential attacker pivot toward high-value intelligence targets. Nation-state actors (APT29, APT28, APT40) specifically use lateral movement to reach systems holding policy documents, intelligence assessments, diplomatic cables, and national security planning materials.

This type of lateral movement is often patient and slow — adversaries may sit on an initial foothold for weeks before pivoting. Any new authentication to restricted systems warrants immediate investigation regardless of the source account's apparent legitimacy.

---

## Microsoft Sentinel KQL

```kql
// SEC-GOV-LM-001 | Frequency: 5m | Lookback: 5m
let RestrictedHosts = (_GetWatchlist('RestrictedGovSystems') | project SearchKey);
let StdITHosts      = (_GetWatchlist('StandardITHosts') | project SearchKey);
// Detection 1: Authentication from standard IT host to restricted system
let NetworkPivot = (
    IdentityLogonEvents
    | where TimeGenerated >= ago(5m)
    | where ActionType == "LogonSuccess"
    | where DestinationDeviceName in~ (RestrictedHosts)
        or DestinationDeviceName has_any (
            "restricted","classified","secret","policy","nsc","jic","intelligence",
            "cabinet","minister","secure","gov-classified","high-side"
        )
    | where DeviceName in~ (StdITHosts)
        or not(DeviceName in~ (RestrictedHosts))
    | project TimeGenerated, AccountName, AccountDomain,
        DeviceName, DestinationDeviceName, Protocol, LogonType
    | extend DetectionType = "StandardIT-to-RestrictedSystem"
);
// Detection 2: RDP to restricted system from unexpected host
let RDPPivot = (
    DeviceLogonEvents
    | where TimeGenerated >= ago(5m)
    | where LogonType == "RemoteInteractive"
    | where ActionType == "LogonSuccess"
    | where RemoteDeviceName in~ (RestrictedHosts)
        or RemoteDeviceName has_any ("restricted","classified","policy","secure","high-side")
    | where not(DeviceName in~ (RestrictedHosts))
    | project TimeGenerated, AccountName, DeviceName, RemoteDeviceName, LogonType
    | extend DetectionType = "RDP-to-RestrictedSystem"
);
NTLMPivot | union RDPPivot
| extend AlertTitle = strcat("GOV RESTRICTED SYSTEM PIVOT: ", DeviceName, " → ", DestinationDeviceName)
| extend SecurityNote = "Escalate to SIRO and DSO immediately. Report to NCSC."
| extend NCSObligation = "Report to NCSC via report.ncsc.gov.uk — nation-state lateral movement pattern"
```

---

## Defender for Identity — MDI Lateral Movement Alerts

Ensure MDI sensors are deployed on all Domain Controllers, including those serving restricted network segments. Key MDI alerts to correlate:
- **Pass-the-Hash attack** — hash-based pivot to restricted system
- **Pass-the-Ticket** — Kerberos ticket reuse
- **Suspected overpass-the-hash** — anomalous Kerberos TGT request
- **Remote code execution attempt** — execution on restricted host

---

## Defender XDR — Advanced Hunting

```kql
// SEC-GOV-LM-001 | Run: Every hour
let Restricted = (_GetWatchlist('RestrictedGovSystems') | project SearchKey);
let Baseline = (
    IdentityLogonEvents
    | where Timestamp between (ago(30d)..ago(1d))
    | where DestinationDeviceName in~ (Restricted)
    | distinct AccountName, DeviceName, DestinationDeviceName
);
IdentityLogonEvents
| where Timestamp >= ago(1h)
| where ActionType == "LogonSuccess"
| where DestinationDeviceName in~ (Restricted)
| join kind=leftanti Baseline on AccountName, DeviceName, DestinationDeviceName
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, Protocol
| order by Timestamp desc
```

---

## Defender for Endpoint — Restricted System Investigation

```kql
// What did the account do on the restricted system after gaining access?
DeviceProcessEvents
| where DeviceName == "<RESTRICTED_HOST>"
| where Timestamp >= "<PIVOT_TIME>"
| where AccountName == "<PIVOTING_ACCOUNT>"
| project Timestamp, FileName, ProcessCommandLine, AccountName, FolderPath, SHA256
| order by Timestamp asc
```

```kql
// Were any files accessed or copied on the restricted system?
DeviceFileEvents
| where DeviceName == "<RESTRICTED_HOST>"
| where Timestamp >= "<PIVOT_TIME>"
| where AccountName == "<PIVOTING_ACCOUNT>"
| project Timestamp, FileName, FolderPath, ActionType, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Immediate escalation (0–5 min)**
Notify DSO (Departmental Security Officer) and SIRO by phone — do not use email.
What is the restricted system? What data/access does it hold?

**Step 2 — Validate the access (5–15 min)**
Is this account authorised to access this restricted system?
Check the access control list for the target system — was this account added recently?

**Step 3 — Source host investigation (15–30 min)**
Run GEN-CA-001 LSASS check on the source IT host — was it compromised first?
Check for prior lateral movement in the 30 days before this event.

**Step 4 — Nation-state attribution (30–60 min)**
Is the movement pattern consistent with known APT TTPs?
- Slow and patient (weeks between hops) = nation-state characteristic
- Use of living-off-the-land (wmic, PsExec, native tools only) = nation-state characteristic
Submit source IP, user agent, and movement timeline to NCSC.

---

## Response Actions

**Immediate**
- [ ] Isolate the source IT host — MDE
- [ ] Revoke the pivoting account's access to the restricted system
- [ ] Notify DSO and SIRO by phone
- [ ] Do NOT alert the affected user — this may compromise the investigation

**Within 1 Hour**
- [ ] Report to NCSC: [report.ncsc.gov.uk](https://report.ncsc.gov.uk) — nation-state lateral movement pattern
- [ ] Preserve all restricted system access logs (do not allow rotation)
- [ ] Assess what information on the restricted system may have been accessed
- [ ] Brief Head of Security and Permanent Secretary / Director General as appropriate

**Post-Incident**
- [ ] Full forensic investigation of the source IT host and all lateral movement hops
- [ ] Review access controls on all restricted systems — ensure zero-trust principles
- [ ] Cabinet Office notification if classified above OFFICIAL

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Authorised IT admin accessing restricted system for maintenance | Must be via approved privileged access workstation (PAW) with pre-approved ITSM ticket |
| New user account — baseline gap | Verify account was legitimately granted access; add to approved list with SIRO approval |

## References
- [MITRE T1021](https://attack.mitre.org/techniques/T1021/)
- [NCSC: Defending government systems](https://www.ncsc.gov.uk/section/government-public-sector/)
- [NCSC: Report an incident](https://report.ncsc.gov.uk)
