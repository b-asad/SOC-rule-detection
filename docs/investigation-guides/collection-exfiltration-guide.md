# Collection & Exfiltration — Tactic Investigation Guide

**Applicable Rules:** GEN-CO-001 · GEN-EF-001 · SEC-HC-CO-001 · SEC-HC-EF-001 · SEC-FS-CO-001 · SEC-FS-EF-001 · SEC-GOV-CO-001 · SEC-GOV-EF-001 · SEC-EDU-CO-001 · SEC-EDU-EF-001 · SEC-MFG-CO-001 · SEC-MFG-EF-001 · SEC-LEG-EF-001 · SEC-RET-CO-001 · SEC-RET-EF-001 · SEC-TECH-EF-001 · SEC-ENRG-CO-001 · SEC-ENRG-EF-001

---

## Triage Decision Tree

```
Collection / Exfiltration alert fires
│
├── GEN-CO-001: Email forwarding rule created?
│   ├── Finance/executive mailbox? → P1 — BEC financial risk assessment
│   └── Any mailbox → P1 — Revoke session, delete rule, reset password
│
├── GEN-EF-001: Abnormal outbound volume?
│   ├── Upload to cloud storage → Investigate destination and content
│   └── Upload to unknown IP → Submit to threat intel, likely C2 exfil
│
├── Sector collection rules (bulk document/data download)?
│   └── → P1/P2 depending on data sensitivity and user role
│
└── Sector exfiltration rules (upload to external service)?
    └── → P1 — Identify data, assess regulatory obligations, block destination
```

---

## Universal Queries

**BEC follow-up — check for financial indicators after forwarding rule:**
```kql
EmailEvents | where SenderFromAddress == "<COMPROMISED_UPN>" | where Timestamp >= ago(7d)
| where RecipientEmailAddress !has "<INTERNAL_DOMAIN>"
| where Subject has_any ("payment","invoice","wire","transfer","urgent","bank","account")
| project Timestamp, RecipientEmailAddress, Subject
```

**Staging check — was data aggregated before exfiltration?**
```kql
DeviceFileEvents | where DeviceName == "<DEVICE>" | where Timestamp between (ago(4h) .. now())
| where FileName has_any (".zip",".7z",".rar",".tar",".gz") and ActionType in ("FileCreated","FileCopied")
| where FolderPath has_any ("Temp","Downloads","Desktop","AppData")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

**Exfiltrating process identification:**
```kql
DeviceNetworkEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| where BytesSent > 100000
| project Timestamp, RemoteIP, RemoteUrl, BytesSent, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by BytesSent desc
```

**USB/removable media check (insider threat):**
```kql
DeviceEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(24h)
| where ActionType in ("UsbDriveMount","RemovableMediaMount","PnpDeviceConnected")
| project Timestamp, DeviceName, AccountName, AdditionalFields
```

---

## Data Sensitivity Assessment

| Data Type | Severity | Regulatory Obligation | Timeline |
|-----------|---------|----------------------|---------|
| Patient PII / medical records | Critical | ICO + NHS SIRO | 72h ICO |
| Financial client data / PCI CHD | Critical | ICO + FCA + card brands | 72h ICO / 24h card brands |
| Government classified documents | Critical | NCSC + Cabinet Office | Immediate |
| Student PII | High | ICO | 72h |
| Proprietary trade secrets / IP | High | Legal / IP Counsel | Immediate |
| Employee personal data | High | ICO | 72h |
| General business data | Medium | Internal only | — |

---

## Escalation Triggers
- Confirmed exfiltration of any personal data → ICO 72h clock starts
- Financial account data exfiltrated → card brand and bank notification
- Patient data exfiltrated → Caldicott Guardian + NHS SIRO + ICO
- Government classified material → NCSC + Cabinet Office
- Active BEC with financial transactions pending → bank fraud team immediately
