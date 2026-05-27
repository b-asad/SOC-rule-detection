# Microsoft Defender for Cloud Apps (MCAS) — Configuration Guide

## App Connector Setup

Connect the following in MCAS → Settings → App connectors:
- [x] Microsoft 365 (required — connects Exchange, SharePoint, OneDrive, Teams)
- [x] Azure (required — connects Azure AD, Azure resources)
- [x] Salesforce (if used by customer)
- [x] ServiceNow (if used by customer)
- [x] Box / Dropbox / Google Workspace (if sanctioned cloud storage in use)

---

## Anomaly Detection Policies — Enable for All Customers

MCAS → Policies → Anomaly detection — enable and configure:

| Policy | Mapped Rule | Sensitivity |
|--------|------------|------------|
| Impossible travel | GEN-IA-002 | Medium initially → High after 30 days |
| Activity from infrequent country | GEN-IA-003 variant | Medium |
| Unusual file download | GEN-EF-001, RA-CO-001, SEC-FS-CO-001 | High |
| Multiple failed login attempts | GEN-CA-002, SEC-EDU-CA-001 | Medium |
| Unusual file deletion | GEN-IM-001 cloud variant | High |
| Suspicious inbox manipulation rules | GEN-CO-001 | High |
| Ransomware activity | GEN-IM-001, GEN-IM-002 | High |

---

## Sector-Specific File Policies

### Healthcare
Policy: Alert on external sharing of files with sensitivity label **Clinical** or containing keywords: `patient`, `nhs number`, `clinical`, `diagnosis`, `medication`.

### Financial Services
Policy: Alert on external sharing of files containing: `account number`, `sort code`, `IBAN`, `portfolio`, `client`, `trading`.

### Government
Policy: Alert on external sharing of files with sensitivity labels **OFFICIAL-SENSITIVE**, **SECRET**, or containing: `policy`, `cabinet`, `classified`.

### Legal
Policy: Alert on external sharing of files containing: `privileged`, `without prejudice`, `legally privileged`, `confidential`, `client`.

### Technology
Policy: Alert on bulk download of files with extensions `.py`, `.js`, `.ts`, `.go`, `.rs`, `.java`, `.cs` from code repositories.

---

## Conditional Access App Control — Recommended for High-Risk Tenants

For customers with high insider threat risk (Financial Services, Legal, Government):
Route high-sensitivity applications through MCAS proxy to:
- Block download of sensitive files from unmanaged devices
- Require MFA on access to sensitive applications
- Record session activity for audit purposes

Configure: MCAS → Policies → Conditional Access App Control policies
