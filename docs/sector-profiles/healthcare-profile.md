# Sector Profile — Healthcare

## Threat Landscape

Healthcare is one of the highest-value sectors for threat actors. Patient records command the highest dark web prices, clinical systems often run legacy OS, and ransomware has direct patient safety implications. Primary threats:

- **Ransomware** — targeting EPR, PACS, pharmacy systems; patient safety risk (Rhysida, LockBit, WannaCry variants)
- **Insider threat** — clinical staff accessing VIP patient records, bulk patient data export
- **Nation-state espionage** — targeting pharmaceutical research, clinical trial data, vaccine development
- **Phishing** — against clinical staff for ransomware delivery or credential theft
- **Medical device exploitation** — targeting networked medical devices on clinical networks

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **NHS DSPT** | Meet all 10 mandatory data security standards | Report to NHS England SIRO immediately |
| **UK GDPR / Data Protection Act 2018** | Protect patient personal data | Notify ICO within 72h |
| **Caldicott Principles** | Patient data used only for legitimate clinical purpose | Notify Caldicott Guardian on any breach |
| **CQC** | Maintain safe clinical operations | Report if patient safety affected |

## Detection Rule Deployment — Healthcare

1. All Generic rules (GEN-*)
2. `SEC-HC-IM-001` — Ransomware on clinical systems (Priority 1 — patient safety)
3. `SEC-HC-CA-001` — Patient record bulk access
4. `SEC-HC-CO-001` — Patient record mass download
5. `SEC-HC-EF-001` — Medical data upload to external service
6. `SEC-HC-IA-001` — Phishing targeting clinical staff
7. `SEC-HC-LM-001` — RDP lateral movement on clinical network

## Required Watchlists — Healthcare

| Watchlist | Content |
|----------|---------|
| `ClinicalHosts` | All EPR, PACS, pharmacy, ward, and radiology hostnames |
| `InternalEmailDomains` | NHS trust email domains |

## Escalation Contacts — Template

- Chief Clinical Information Officer (CCIO) — clinical system impact
- Chief Information Officer (CIO) — IT escalation
- Caldicott Guardian — patient data breach
- Data Protection Officer (DPO) — GDPR obligations
- NHS England SIRO contact — mandatory reporting
- ICO breach reporting: 0303 123 1113
