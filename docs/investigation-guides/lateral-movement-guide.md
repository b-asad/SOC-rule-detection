# Lateral Movement — Tactic Investigation Guide

**Applicable Rules:** GEN-LM-001 · GEN-LM-002 · SEC-HC-LM-001 · SEC-FS-LM-001 · SEC-GOV-LM-001 · SEC-MFG-LM-001 · SEC-ENRG-LM-001 · SEC-RET-LM-001

---

## Triage Decision Tree

```
Lateral Movement alert fires
│
├── GEN-LM-001: Pass-the-Hash (NTLM anomaly)?
│   ├── Source device: check for prior LSASS dump (GEN-CA-001)
│   └── → P1 — Isolate both hosts, reset abused account, search for further hops
│
├── GEN-LM-002: RDP to new host?
│   ├── Workstation-to-workstation RDP?
│   │   └── YES → Almost always malicious — P1
│   └── Admin-to-server with ITSM ticket? → P4, document only
│
├── Sector network boundary pivots (SEC-FS/MFG/ENRG/HC/GOV-LM-001)?
│   └── → P1 IMMEDIATELY — Network boundary violation, sector escalation
│
└── SEC-RET-LM-001: POS network spread?
    └── → P1 — CDE boundary assessment, PCI DSS breach evaluation
```

---

## Universal Queries

**Credential origin — was source device compromised first?**
```kql
DeviceEvents | where DeviceName == "<SOURCE_DEVICE>"
| where Timestamp between (ago(24h) .. now())
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

**What attacker did on destination host:**
```kql
DeviceProcessEvents | where DeviceName == "<DEST_DEVICE>"
| where Timestamp >= "<PIVOT_TIME>" and AccountName == "<PIVOTING_ACCOUNT>"
| project Timestamp, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp asc
```

**Further lateral movement hops from destination:**
```kql
IdentityLogonEvents | where DeviceName == "<DEST_DEVICE>"
| where Timestamp >= "<PIVOT_TIME>"
| where ActionType == "LogonSuccess" and Protocol in ("Ntlm","Rdp","Kerberos")
| project Timestamp, AccountName, DestinationDeviceName, Protocol
| order by Timestamp asc
```

**Full lateral movement chain — follow all hops:**
```kql
let StartTime = "<INITIAL_COMPROMISE_TIME>";
let InitialAccount = "<COMPROMISED_ACCOUNT>";
IdentityLogonEvents
| where Timestamp >= StartTime
| where AccountName == InitialAccount or AccountName has InitialAccount
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, Protocol
| order by Timestamp asc
// Each DestinationDeviceName becomes the next hop to investigate
```

---

## Sector-Specific Escalation

| Network Boundary Crossed | Immediate Action | Notify |
|--------------------------|-----------------|--------|
| IT → Trading network (FS) | Revoke trading access, notify Compliance | Head of Technology Risk, FCA (if trading impacted) |
| IT → OT network (Manufacturing) | Consider physical network isolation | Plant Manager, OT Security, NCSC (NIS2) |
| IT → SCADA/Energy systems | Physical isolation, manual control mode | Control Room Engineer, NCSC, Ofgem/Ofwat |
| Standard IT → Clinical systems (Healthcare) | Clinical downtime procedures | CCIO, NHS SIRO |
| Standard IT → Restricted system (Government) | Immediate DSO notification | DSO, SIRO, NCSC |

---

## Escalation Triggers
- Lateral movement confirmed reaching OT, clinical, trading, or classified systems → P1 + sector escalation
- > 3 devices confirmed compromised → outbreak protocol, consider network segmentation
- Domain controller reached → P1 + CISO + possible full domain compromise assessment
