# Sector Profile — Legal

## Threat Landscape

Law firms hold irreplaceable client privileged communications, commercially sensitive transaction details (M&A, litigation), and large client account funds. They are consistently targeted by nation-state actors (for intelligence on M&A and geopolitical matters), organised crime (for direct financial theft via conveyancing/BEC fraud), and corporate espionage. Primary threats:

- **BEC / conveyancing fraud** — redirecting client account transfers (highest financial risk)
- **Ransomware** — encrypting matter management and DMS systems
- **Nation-state espionage** — M&A intelligence, political litigation files, diplomatic legal matters
- **Insider threat** — departing fee-earners taking client files and contacts
- **Phishing** — targeting fee-earners and accounts staff

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **SRA Code of Conduct** | Protect client confidentiality (Rule 6.3) | Notify affected clients promptly |
| **SRA Accounts Rules** | Protect client money | Notify SRA immediately if client money at risk |
| **UK GDPR** | Client personal data | Notify ICO within 72h |
| **ICO** | Data controller obligations | 72h notification |

## Detection Rule Deployment — Legal

1. All Generic rules (GEN-*)
2. `SEC-LEG-IA-001` — BEC invoice/conveyancing fraud
3. `SEC-LEG-CA-001` — Matter system credential theft
4. `SEC-LEG-IM-001` — DMS ransomware
5. `SEC-LEG-EF-001` — Client privileged data exfiltration

## Required Watchlists — Legal

| Watchlist | Content |
|----------|---------|
| `LegalSystemHosts` | DMS, matter management, conveyancing system hostnames |
| `InternalEmailDomains` | Firm email domains including subsidiaries |

## Escalation Contacts — Template

- Managing Partner — significant incidents
- COLP (Compliance Officer for Legal Practice)
- COFA (Compliance Officer for Finance and Administration) — client money events
- SRA reporting: 0370 606 2555
