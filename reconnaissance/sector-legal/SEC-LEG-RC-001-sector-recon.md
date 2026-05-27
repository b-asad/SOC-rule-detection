# SEC-LEG-RC-001 — Reconnaissance: Legal Infrastructure Targeting

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-LEG-RC-001` |
| **MITRE Tactic** | Reconnaissance |
| **Sector** | **Legal** |
| **Severity** | **Medium** |
| **Priority** | **P2** |
| **MS Tools** | Sentinel |
| **Log Source** | WAF / Firewall logs · `ThreatIntelligenceIndicator` |

## Description

Applies `GEN-RC-001` (active scanning) detection to infrastructure specific to the legal sector, plus sector-specific threat intelligence feeds and targeted reconnaissance indicators.

**Deploy alongside GEN-RC-001** — this adds sector context and targeted threat actor tracking.

## Sector-Specific Reconnaissance Threats

The legal sector faces targeted reconnaissance from:
- Threat actors known to target this sector (see sector-profile documentation)
- Automated scanning for sector-specific CVEs and platforms
- Brand-abuse and typosquatting domains targeting sector organisations

## Detection Approach

Extend `GEN-RC-001` with:
- Sector-specific application fingerprints in WAF rule matching
- Sector-specific threat intel feeds
- Brand monitoring for sector-specific lookalike domains

## Response Actions
- Follow GEN-RC-001 response actions
- Notify sector-specific threat intelligence sharing group (ISAC if applicable)
- Heightened monitoring for 30 days following reconnaissance detection

## References
- Base rule: `GEN-RC-001`
