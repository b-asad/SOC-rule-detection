# SEC-RET-RD-001 — Resource Development: Sector-Targeted Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-RD-001` |
| **MITRE Tactic** | Resource Development |
| **Sector** | **Retail** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 |
| **Log Source** | `ThreatIntelligenceIndicator` · `EmailEvents` |

## Description

Applies `GEN-RD-001` / `GEN-RD-003` detection to retail-specific resource development activity — OAuth applications impersonating sector platforms, lookalike domains targeting sector organisations, and infrastructure registered to target this sector specifically.

## Sector-Specific Indicators

Lookalike domains to monitor for this sector:
- Domains mimicking sector regulators (e.g., `ret-regulator.com`)
- Domains mimicking common sector software vendors
- Domains with sector keywords combined with urgency terms

## Detection Approach

Extend `GEN-RD-001` watchlist `InternalEmailDomains` with sector-specific vendor and partner domains.
Monitor for OAuth applications impersonating sector-specific platforms.

## References
- Base rules: `GEN-RD-001`, `GEN-RD-003`
