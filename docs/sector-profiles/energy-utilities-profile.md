# Sector Profile — Energy & Utilities

## Threat Landscape

Energy and utilities are classified as Critical National Infrastructure (CNI). Nation-state actors pre-position in energy sector networks years in advance of potential conflict or coercive use. Physical disruption of power, water, or gas supply is the ultimate objective. Primary threats:

- **Nation-state pre-positioning** — VOLTZITE/Volt Typhoon (China), Sandworm (Russia), XENOTIME/Triton actor
- **IT-to-OT pivoting** — using IT compromise to reach industrial control systems
- **SCADA/ICS targeting** — reconnaissance, configuration theft, setpoint manipulation
- **Ransomware** — operational disruption for ransom (Colonial Pipeline model)
- **Physical safety system attacks** — targeting safety instrumented systems (SIS/ESD)

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **NIS2 Directive** | Mandatory for energy operators | Report to NCSC within 24h |
| **NCSC CAF** | Cyber Assessment Framework | Regular CAF assessment |
| **Ofgem/Ofwat** | Sector regulator requirements | Notify sector regulator |
| **CPNI** | CNI guidance | CPNI/NCSC coordination |
| **UK GDPR** | Customer personal data | Notify ICO within 72h |

## Detection Rule Deployment — Energy & Utilities

1. All Generic rules (GEN-*)
2. `SEC-ENRG-IA-001` — SCADA external access (Priority 1 — CNI risk)
3. `SEC-ENRG-LM-001` — IT-to-OT pivot
4. `SEC-ENRG-CA-001` — ICS engineering credential theft
5. `SEC-ENRG-IM-001` — Grid disruption indicators
6. `SEC-ENRG-CO-001` — Grid topology reconnaissance
7. `SEC-ENRG-EF-001` — Grid configuration exfiltration

## Required Watchlists — Energy & Utilities

| Watchlist | Content |
|----------|---------|
| `OTNetworkRanges` | All OT/ICS subnet CIDRs |
| `OTAssets` | All SCADA, EMS, DMS, substation hostnames |
| `EnergySystemHosts` | Energy management system hostnames |
| `ITNetworkRanges` | IT network CIDRs |

## Escalation Contacts — Template

- Control Room Engineer / Shift Manager — operational impact
- CISO / Head of Cyber Security
- NCSC reporting (NIS2): report.ncsc.gov.uk
- Sector regulator: Ofgem / Ofwat / ONR
- CPNI: 020 7233 7171
