# SEC-EDU-IM-001 — Education: Ransomware Targeting Student and Research Systems

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-EDU-IM-001` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | T1486 — Data Encrypted for Impact |
| **Sector** | **Education** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` · `DeviceFileEvents` (MDE) |
| **Sector Context** | Universities, schools, academies, research institutions, student information systems |
| **Created** | May 2026 |

---

## Description

Education is consistently the most-targeted sector for ransomware globally due to large attack surfaces (student-owned devices, open networks), valuable research data, and typically limited security budgets. This rule detects ransomware precursor and active encryption events on education infrastructure, with particular focus on student record systems (SITS, Unit-e, Banner), research data repositories, and library systems.

**Regulatory:** UK GDPR (student personal data), JISC/Cyber Essentials, ICO notification within 72 hours.

---

## Microsoft Sentinel KQL

```kql
// SEC-EDU-IM-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
let EduHosts = (_GetWatchlist('EducationCriticalHosts') | project SearchKey);
let ShadowDeletion = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where DeviceName in~ (EduHosts)
        or DeviceName has_any ("sits","banner","unit-e","moodle","vle","registry","library","research","hpc","cluster")
    | where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows","Delete Shadows"))
        or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
        or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
    | extend DetectionType = "ShadowCopyDeletion"
);
let ResearchDataKills = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where FileName in~ ("net.exe","sc.exe","taskkill.exe")
    | where ProcessCommandLine has_any ("moodle","sits","vle","banner","library","research","hpc","matlab","stata")
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
    | extend DetectionType = "EducationServiceTermination"
);
ShadowDeletion | union ResearchDataKills
| extend AlertTitle = strcat("Ransomware Indicator on Education System: ", DeviceName)
| extend StudentDataRisk = "Student records, research data, and examination content may be at risk"
| extend GDPRObligation = "Notify ICO within 72h if student personal data affected"
```

---

## Investigation Guide

**Step 1 — Critical System Impact (< 5 min)**
Are examinations currently in progress? Is this during an assessment period?
- If yes: contact Registry and IT Director simultaneously
- Active examination systems being encrypted = immediate exam board notification required

**Step 2 — Research Data Assessment (5–15 min)**
Are any research compute clusters or HPC nodes affected?
Contact Research IT — are there active long-running computations? Grant-funded datasets?
Research data loss may require funder notification (UKRI, Wellcome Trust, etc.)

**Step 3 — Student Record Systems (15–30 min)**
Are SITS/Banner/Unit-e systems affected? These contain student PII — UK GDPR breach if encrypted.
Notify Data Protection Officer and Registry.

---

## Response Actions
**Immediate**
- [ ] Isolate all affected systems — MDE
- [ ] Notify IT Director, Registrar, and DPO simultaneously
- [ ] If examinations in progress: notify Exams Officer and activate academic continuity plan

**Regulatory**
- [ ] Notify ICO within 72h if student personal data encrypted
- [ ] Notify JISC (cybersecurity advice for education sector)
- [ ] Notify research funders if funded data may be lost

## References
- [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
- [JISC: Cybersecurity for education](https://www.jisc.ac.uk/cyber-security)
- [ICO: Report a breach](https://ico.org.uk/for-organisations/report-a-breach/)
