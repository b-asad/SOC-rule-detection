# Sector Profile — Manufacturing

## Threat Landscape

Manufacturing combines IT (enterprise systems) with OT (operational technology controlling physical production processes), creating a unique attack surface. A successful attack can cause production downtime, physical equipment damage, and supply chain disruption. Primary threats:

- **Ransomware** — encrypting ERP, MES, and production systems to halt manufacturing (LockBit, BlackCat, Cl0p)
- **Nation-state OT targeting** — VOLTZITE, Sandworm, APT33 targeting industrial control systems
- **IP theft** — CAD designs, proprietary production processes, materials formulations
- **IT-to-OT pivoting** — using IT compromise as a foothold to reach industrial control systems
- **Supply chain attacks** — targeting manufacturing suppliers and OEM vendors

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **NIS2 Directive** | Mandatory for critical manufacturing | Report to NCSC within 24h |
| **ISO 27001** | Information security management | Contractual / certification |
| **HSE** | Report if safety systems affected | RIDDOR notification |
| **UK GDPR** | Employee/customer personal data | Notify ICO within 72h |

## Detection Rule Deployment — Manufacturing

1. All Generic rules (GEN-*)
2. `SEC-MFG-LM-001` — IT-to-OT network pivot (Priority 1 — physical risk)
3. `SEC-MFG-IA-001` — Phishing targeting engineering staff
4. `SEC-MFG-CA-001` — OT engineering credential theft
5. `SEC-MFG-IM-001` — OT ransomware
6. `SEC-MFG-CO-001` — Product design IP theft
7. `SEC-MFG-EF-001` — OT configuration exfiltration

## Required Watchlists — Manufacturing

| Watchlist | Content |
|----------|---------|
| `OTNetworkRanges` | All OT/ICS subnet CIDRs |
| `ITNetworkRanges` | All IT subnet CIDRs |
| `OTEngineeringHosts` | OT engineering workstation hostnames |

## Escalation Contacts — Template

- Plant/Site Manager — production impact
- OT Security team lead — OT-specific response
- Head of Engineering — IP theft
- NCSC reporting (NIS2): report.ncsc.gov.uk
