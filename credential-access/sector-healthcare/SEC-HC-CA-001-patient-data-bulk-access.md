# SEC-HC-CA-001 — Healthcare: Unauthorised Bulk Patient Record Access

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-HC-CA-001` |
| **MITRE Tactic** | Collection |
| **MITRE Technique** | T1530 — Data from Cloud Storage / T1213 — Data from Information Repositories |
| **Sector** | **Healthcare** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | EPR Application Audit Logs · `CloudAppEvents` (MCAS) · Custom EPR log table |
| **Sector Context** | EPR access, patient record viewing, clinical application audit logs |
| **Created** | May 2026 |

---

## Description

Detects a clinician or staff member accessing an unusually high number of patient records relative to their clinical role and normal access pattern. Healthcare insider threat accounts for a significant proportion of patient data breaches — staff accessing VIP patient records (celebrities, colleagues, executives), accessing records of people they know personally, or bulk-exporting patient lists.

This is a **UK GDPR / NHS DSPT** mandatory report event if unauthorised access to patient records is confirmed. The Caldicott Guardian must be notified.

**Common scenarios:** A receptionist accessing hundreds of patient medication records (not their role), a nurse viewing records of patients not under their care, an administrator bulk-exporting patient contact lists.

---

## Microsoft Sentinel KQL

```kql
// SEC-HC-CA-001 | Frequency: 15m | Lookback: 1h | Threshold: > 0
// Requires EPR/clinical system audit logs forwarded to Sentinel
// Table name: adjust 'EPRAuditLog_CL' to match your customer's log source
EPRAuditLog_CL
| where TimeGenerated >= ago(1h)
| where EventType_s in ("PatientRecordView","PatientRecordExport","PatientSearch","RecordDownload")
| summarize
    RecordCount     = count(),
    UniquePatients  = dcount(PatientID_s),
    Actions         = make_set(EventType_s, 5),
    FirstAccess     = min(TimeGenerated),
    LastAccess      = max(TimeGenerated)
    by UserId_s, UserRole_s, Department_s, ClientIP_s
| where UniquePatients > 50   // More than 50 unique patients in 1 hour is anomalous for most roles
| extend AnomalyRatio = round(todouble(UniquePatients) / 60.0, 1)  // Patients per minute
| extend AlertTitle = strcat("Bulk Patient Record Access by ", UserId_s, " (", UserRole_s, ")")
| extend CaldicottRisk = "Potential patient data breach. Caldicott Guardian notification may be required."
| extend RegulatoryObligation = "UK GDPR Article 33 — notify ICO within 72h if patient rights affected"
| order by UniquePatients desc
```

---

## Defender for Cloud Apps — CASB Policy

If EPR is cloud-hosted (e.g., hosted EMIS, SystmOne Online, Epic cloud):
- Create an Activity policy: High volume of patient record views by a single user
- Filter: Activity = "View Record" | Count > 50 | Time window = 60 minutes
- Alert severity: High
- Governance: Suspend user session (with CCIO pre-approval for clinical accounts)

---

## Investigation Guide

**Step 1 — Clinical Role Context (< 10 min)**
What is the user's clinical role? A GP viewing many records per hour during a busy clinic is normal. A medical secretary bulk-viewing medication records is not.
- Check the user's department and normal access pattern (30-day baseline)
- Contact the clinical line manager (not the user) — could this be explained by legitimate care delivery?

**Step 2 — Patient Sensitivity Check (10–25 min)**
Were any of the accessed patients:
- VIPs (local celebrities, politicians, known public figures)?
- Staff members or their relatives?
- People connected to the accessing staff member (same postcode, same GP registration)?

VIP patient access is almost always a reportable breach.

**Step 3 — Caldicott Assessment (25–40 min)**
Under the Caldicott Principles, was the access:
- Justified by a legitimate clinical purpose?
- Limited to the minimum necessary patient information?
- On a "need to know" basis?

If any answer is no: notify the Caldicott Guardian and Data Protection Officer.

---

## Response Actions
**Immediate**
- [ ] Disable the staff member's EPR access pending investigation
- [ ] Notify line manager and HR
- [ ] Preserve EPR audit logs as evidence
- [ ] Notify Caldicott Guardian and Data Protection Officer

**Regulatory**
- [ ] Assess ICO notification requirement (UK GDPR Article 33 — 72h window)
- [ ] Complete DSPT incident report
- [ ] Notify NHS England if trust-level data breach

## References
- [NHS: Caldicott Principles](https://www.gov.uk/government/publications/the-caldicott-principles)
- [ICO: Healthcare data breaches](https://ico.org.uk/for-organisations/report-a-breach/)
- [NHS DSPT](https://www.dsptoolkit.nhs.uk)
