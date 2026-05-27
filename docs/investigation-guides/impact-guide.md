# Impact — Tactic Investigation Guide

**Applicable Rules:** GEN-IM-001 · GEN-IM-002 · SEC-HC-IM-001 · SEC-EDU-IM-001 · SEC-MFG-IM-001 · SEC-RET-IM-001 · SEC-FS-IM-001 · SEC-LEG-IM-001 · SEC-GOV-IM-001 · SEC-TECH-IM-001 · SEC-ENRG-IM-001

---

## CRITICAL: Contain first. Investigate second.

When an Impact-tactic rule fires you are likely in an active ransomware, destructive attack, or service disruption. Every minute of delay expands the blast radius.

---

## Ransomware Response Decision Tree

```
GEN-IM-001 or GEN-IM-002 fires
│
├── STEP 1: Isolate device IMMEDIATELY (before reading further)
│
├── STEP 2: Blast radius — how many devices?
│   ├── 1 device → contained — continue investigation
│   ├── 2–5 devices → active spread — emergency network segmentation
│   └── 5+ devices → outbreak — activate BCP immediately
│
├── STEP 3: Notify
│   ├── SOC Manager → Head of Security Services → Customer CISO (all by phone)
│   └── Sector contacts (see sector escalation table below)
│
├── STEP 4: Backup integrity
│   ├── Clean backups accessible? → Begin recovery planning
│   └── Backups encrypted too? → Scope data loss, consider options
│
├── STEP 5: Identify ransomware family
│   └── Submit ransom note to id-ransomware.malwarehunterteam.com
│       └── Known decryptor? → Check nomoreransom.org before any other advice
│
└── STEP 6: Regulatory notifications (see table below)
```

---

## Key Queries

**Patient zero — first device infected:**
```kql
DeviceProcessEvents | where Timestamp >= ago(24h)
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows"
| summarize FirstSeen=min(Timestamp) by DeviceName, AccountName
| order by FirstSeen asc
// Top row = patient zero
```

**Blast radius — all affected devices:**
```kql
DeviceProcessEvents | where Timestamp >= ago(2h)
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows"
| distinct DeviceName, AccountName, Timestamp | order by Timestamp asc
```

**Ransomware family — ransom note identification:**
```kql
DeviceFileEvents | where Timestamp >= ago(2h)
| where FileName has_any ("README","DECRYPT","HOW_TO","ransom","RECOVER","YOUR_FILES","RESTORE","PAYMENT","LOCKED","NOTE")
| project Timestamp, DeviceName, FileName, FolderPath
// Submit ransom note content to id-ransomware.malwarehunterteam.com
```

**Encryption scope:**
```kql
DeviceFileEvents | where Timestamp >= ago(2h) | where ActionType == "FileModified"
| summarize EncryptedFiles=count(), AffectedFolders=dcount(FolderPath) by DeviceName
| order by EncryptedFiles desc
```

---

## Sector-Specific Impact Priorities

| Sector | Critical System Restoration Order | Sector Escalation |
|--------|----------------------------------|-------------------|
| Healthcare | Emergency dept → Pharmacy → EPR → PACS → Scheduling | CCIO, NHS SIRO, NHS England |
| Manufacturing | Safety systems → Production control → ERP → Admin | Plant Manager, NCSC (NIS2) |
| Financial Services | Payment gateway → Core banking → OMS → Admin | CTO, FCA (DORA 4h) |
| Education | Exam systems (if in-session) → SIS → VLE → Research | Registrar, DPO, JISC |
| Retail | POS terminals → Inventory → ERP → Admin | Operations Director, Acquiring Bank |
| Legal | DMS → Matter management → Email → Admin | Managing Partner, COLP, SRA |
| Energy | Safety systems → Control systems → SCADA → Admin | Control Room, NCSC, Ofgem/Ofwat |

---

## Regulatory Notifications by Sector

| Sector | Regulation | Notification Body | Timeline |
|--------|-----------|------------------|---------|
| All | UK GDPR Art.33 | ICO | 72 hours |
| Healthcare | NHS DSPT | NHS England SIRO | Immediate |
| Financial Services | DORA Art.19 | FCA / PRA | 4 hours (major incidents) |
| Financial Services | PCI DSS (if CHD) | Acquiring bank / card brands | 24 hours |
| Manufacturing/Energy | NIS2 Art.23 | NCSC | 24 hours |
| Government | GovAssure | Cabinet Office | Immediate |
| Legal | SRA Code 6.3 | SRA (if client data) | Prompt |

---

## Evidence Preservation Before Recovery

- [ ] MDE memory dump collection (before any reboot)
- [ ] Export all relevant Sentinel alerts and incident timeline
- [ ] Photograph/screenshot any ransomware messages on screens
- [ ] Preserve ransom note files with original timestamps
- [ ] Document: first alert time, isolation time, recovery start time, backup date used
- [ ] Forensic disk images of patient zero and high-value hosts
