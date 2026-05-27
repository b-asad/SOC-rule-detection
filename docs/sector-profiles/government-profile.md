# Sector Profile — Government

## Threat Landscape

Government organisations are primary targets for nation-state espionage. The combination of classified policy material, diplomatic intelligence, defence planning, and national security information makes them the highest-value intelligence targets globally. Primary threats:

- **Nation-state APTs** — APT28 (Russia/GRU), APT29 (Russia/SVR), APT40 (China/MSS), Lazarus (North Korea)
- **Credential theft and lateral movement** — patient, persistent pivoting toward classified systems
- **Spearphishing** — targeted campaigns against Ministers, senior civil servants, advisors
- **Supply chain compromise** — targeting government suppliers to reach department infrastructure
- **Hacktivism** — website defacement, DDoS, data leaks for political messaging

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **GovAssure** | Annual cyber assurance assessment | Report to DSIT |
| **NCSC CAF** | Cyber Assessment Framework compliance | Report significant incidents to NCSC |
| **Cyber Essentials+** | Mandatory for central government | Immediate escalation |
| **UK GDPR** | Citizen personal data | Notify ICO within 72h |
| **Official Secrets Act 1989** | Protection of classified material | Law enforcement if breach |

## Detection Rule Deployment — Government

1. All Generic rules (GEN-*)
2. `SEC-GOV-IA-001` — Nation-state spearphishing
3. `SEC-GOV-CA-001` — Privileged account spray
4. `SEC-GOV-LM-001` — Classified system pivot
5. `SEC-GOV-CO-001` — Policy document bulk access
6. `SEC-GOV-IM-001` — Website defacement
7. `SEC-GOV-EF-001` — Classified data exfiltration

## Required Watchlists — Government

| Watchlist | Content |
|----------|---------|
| `RestrictedGovSystems` | Restricted/classified system hostnames |
| `PrivilegedGovAccounts` | SCS, ministerial, and IT admin UPNs |
| `GovernmentEmailDomains` | All `.gov.uk`, `.mod.uk`, `.police.uk` domains |

## Escalation Contacts — Template

- Departmental Security Officer (DSO)
- Senior Information Risk Owner (SIRO)
- NCSC reporting: report.ncsc.gov.uk
- Cabinet Office (for classified material breaches)
