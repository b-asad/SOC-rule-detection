# SEC-HC-IM-001 — Healthcare: Ransomware Targeting Clinical Systems

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-HC-IM-001` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | T1486 — Data Encrypted for Impact |
| **Sector** | **Healthcare** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` · `DeviceFileEvents` (MDE) |
| **Sector Context** | NHS trusts, private hospitals, GP practices, clinical networks, medical device networks |
| **Created** | May 2026 |

---

## Description

Ransomware deployment in healthcare environments carries immediate patient safety implications beyond the typical IT impact. Clinical systems — PACS (radiology), EPR (electronic patient records), pharmacy systems, theatre scheduling, and medical device networks — being encrypted can directly endanger patient lives by preventing access to medication records, imaging results, and clinical care plans.

This rule combines shadow copy deletion detection with mass file modification on hosts tagged as clinical or healthcare infrastructure. It also monitors for the specific process kill patterns used by healthcare-targeting ransomware (WannaCry variants, Conti, BlackCat, Rhysida) to disable clinical system services before encryption.

**Regulatory:** NHS Data Security and Protection Toolkit Requirement 9. Mandatory reporting to NHS England SIRO and potentially to ICO within 72 hours.

---

## Microsoft Sentinel KQL

```kql
// SEC-HC-IM-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
// Requires clinical system hosts tagged in ClinicalHosts watchlist
let ClinicalHosts = (_GetWatchlist('ClinicalHosts') | project SearchKey);
// Detection 1: Shadow copy deletion (ransomware precursor) on clinical hosts
let ShadowDeletion = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where DeviceName in~ (ClinicalHosts)
        or DeviceName has_any ("pacs","epr","emr","pharmacy","radiology","theatre","ris","lis","his","clinical","ward")
    | where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows","Delete Shadows"))
        or (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("shadowcopy delete"))
        or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Win32_ShadowCopy","vssadmin"))
        or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
    | extend DetectionType = "ShadowCopyDeletion"
);
// Detection 2: Healthcare-specific service termination before encryption
let ServiceKills = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where DeviceName in~ (ClinicalHosts)
        or DeviceName has_any ("pacs","epr","pharmacy","clinical","ward")
    | where FileName in~ ("net.exe","sc.exe","taskkill.exe")
    | where ProcessCommandLine has_any (
        "mirth","mirth connect","ensemble","epic","meditech","cerner",
        "allscripts","nhs","inps","emis","vision","systmone","tpp",
        "InterSystems","HealthConnect","sql server","oracle","mysql"
    )
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
    | extend DetectionType = "ClinicalServiceTermination"
);
// Detection 3: Mass file modification on clinical hosts
let MassEncryption = (
    DeviceFileEvents
    | where TimeGenerated >= ago(5m)
    | where DeviceName in~ (ClinicalHosts)
        or DeviceName has_any ("pacs","epr","pharmacy","clinical")
    | where ActionType == "FileModified"
    | summarize FileCount=count() by DeviceName, InitiatingProcessFileName, bin(TimeGenerated,1m)
    | where FileCount > 50
    | where InitiatingProcessFileName !in~ ("MsMpEng.exe","BackupAgent.exe","OneDrive.exe")
    | extend DetectionType = "MassFileModification"
    | project TimeGenerated, DeviceName, InitiatingProcessFileName, FileCount, DetectionType
);
ShadowDeletion | union ServiceKills
| extend AlertTitle = strcat("CRITICAL: Probable Ransomware on Clinical System ", DeviceName)
| extend PatientSafetyRisk = "Clinical systems may be unavailable. Assess patient safety impact immediately."
| extend RegulatoryObligation = "NHS DSPT Requirement 9. Potential ICO notification within 72h. Notify NHS England SIRO."
```

---

## Defender XDR — Advanced Hunting

```kql
// SEC-HC-IM-001 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where DeviceName has_any ("pacs","epr","emr","pharmacy","radiology","clinical","ward","ris","lis")
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Win32_ShadowCopy","vssadmin"))
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

---

## Investigation Guide

### Step 1 — Patient Safety Assessment (0–5 minutes, SIMULTANEOUS with containment)

While isolating the device, notify in parallel:
1. **Chief Clinical Information Officer (CCIO)** — can clinical operations continue safely?
2. **Ward managers / clinical leads** — which clinical functions are affected?
3. **Pharmacy** — are medication records accessible? Is there a manual fallback?
4. **Radiology / PACS** — can imaging be accessed? Are emergency scans possible?

**Patient safety considerations:**
- ICU/ITU patients with medication infusions controlled by networked systems
- Theatre cases scheduled for the next 24 hours
- Emergency department — can triage proceed without EPR access?
- Patients currently in treatment who need medication verification

### Step 2 — Clinical Downtime Procedures (5–15 minutes)

Activate clinical downtime procedures:
- Paper-based medication administration records
- Verbal handover for in-progress patient care
- Manual lab result reporting
- Contact NHSE regional team if NHS trust

### Step 3 — Blast Radius — Clinical Network (15–30 minutes)

```kql
// Which clinical systems are affected?
DeviceProcessEvents
| where Timestamp between (ago(2h) .. now())
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows"
| distinct DeviceName, Timestamp
| order by Timestamp asc
```

Are medical devices (infusion pumps, monitors) on the same network segment as infected hosts? If yes: immediate physical network isolation may be required — consult with Biomedical Engineering.

### Step 4 — Backup and Recovery Planning (30–60 minutes)

- Identify the most recent clean backup for each clinical system
- For EPR: contact the system vendor (Epic, Cerner, EMIS, SystmOne) for emergency recovery support
- For PACS: contact vendor for emergency image access procedures

---

## Response Actions

**Immediate (P1 — within 15 minutes)**
- [ ] Isolate ALL affected hosts — MDE portal
- [ ] Notify CCIO, CMO/Medical Director, and CIO simultaneously
- [ ] Activate clinical downtime procedures — paper records, verbal handover
- [ ] Notify NHS England SIRO (for NHS organisations)
- [ ] Contact clinical system vendors for emergency support

**Regulatory (within 72 hours)**
- [ ] Report to NHS England Data Security Centre if NHS trust affected
- [ ] Notify ICO if patient personal data was accessed or encrypted (UK GDPR 72h window)
- [ ] Complete DSPT incident report (Requirement 9.6)
- [ ] Brief the Trust Board within 24 hours

**Recovery**
- [ ] Prioritise restoration in patient safety order: EPR → pharmacy → PACS → scheduling
- [ ] Do NOT reconnect to network until all hosts are confirmed clean
- [ ] Conduct full network re-architecture review before reconnection

---

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Authorised patching requiring VSS cleanup | Suppress ONLY during confirmed maintenance window with CISO approval; never suppress the clinical service termination detection |

---

## References

- [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
- [NHS DSPT: Data security incident management](https://www.dsptoolkit.nhs.uk)
- [NCSC: Ransomware guidance for healthcare](https://www.ncsc.gov.uk/ransomware/home)
- [ICO: Reporting data breaches](https://ico.org.uk/for-organisations/report-a-breach/)
