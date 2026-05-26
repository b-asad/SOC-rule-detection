# Microsoft Defender for Cloud Apps (MCAS) — Configuration Guide

## App Connector Setup (required for cloud app visibility)
Connect these apps in MCAS → Settings → App connectors:
- [x] Microsoft 365 (Office 365 connector)
- [x] Azure (Azure connector)
- [x] Salesforce (if used by customer)
- [x] Box / Dropbox / Google Workspace (if sanctioned)

## Conditional Access App Control
For sensitive applications, route traffic through MCAS proxy:
- Block download of sensitive files from unmanaged devices
- Require MFA on-access for sensitive data labels

## Anomaly Detection Policies (Enable All)
MCAS → Policies → Anomaly detection:
- [x] Impossible travel ← correlates with GEN-IA-002
- [x] Activity from infrequent country
- [x] Unusual file download ← correlates with RA-CO-001, RF-CO-001
- [x] Unusual multiple file deletion ← correlates with GEN-IM-001
- [x] Multiple failed login attempts ← correlates with GEN-CA-002, RA-CA-001
- [x] Suspicious inbox manipulation rules ← correlates with GEN-CO-001

## File Policies for Retail Sectors
**Retail General:** Alert on external sharing of files containing: "card number", "CVV", "track data", "PAN"
**Food & Grocery:** Alert on external sharing of files in allergen, recall, or supplier-compliance classified sites
**Fashion & Apparel:** Alert on mass download of `.ai`, `.psd`, `.cad`, `.dwg` files from design libraries
