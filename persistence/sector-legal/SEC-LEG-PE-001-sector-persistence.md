# SEC-LEG-PE-001 — Legal: Registry Run Key / Account Persistence

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-LEG-PE-001` |
| **MITRE Tactic** | Persistence |
| **Sector** | **Legal** |
| **Severity** | See base rule `GEN-PE-001` — apply same severity |
| **Priority** | See base rule `GEN-PE-001` |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | See `GEN-PE-001` |
| **Sector Context** | Fee-earner workstations, DMS hosts, matter management servers |
| **Regulatory** | SRA, UK GDPR, ICO |

## Description

This rule applies the `GEN-PE-001` detection logic scoped to **Legal** infrastructure — restricting detection to hosts and systems specific to this sector using the watchlist and naming patterns below. The full KQL, investigation guide, and response actions from `GEN-PE-001` apply; this file adds the sector-specific host scope, context, and regulatory obligations.

**Deploy this rule in addition to `GEN-PE-001` — not instead of it.**

## Sentinel KQL — Sector-Scoped Variant

```kql
// SEC-LEG-PE-001 | Sector scope applied to GEN-PE-001
// Full query: copy from GEN-PE-001 and add the WHERE clause below
// Sector host filter — add to the base query:
// | where DeviceName has_any ("<LEGAL-HOST-PATTERNS>")
//     or DeviceName in~ (_GetWatchlist('LegalHosts') | project SearchKey)
// This surfaces Legal-specific alerts separately in the Sentinel incidents queue
// and enables sector-specific playbook routing and escalation paths.
```

Alternatively, create a copy of the `GEN-PE-001` Sentinel Analytics Rule with:
- Rule name prefixed `SEC-LEG-PE-001`
- Add sector host filter to the WHERE clause
- Assign sector-specific playbook: `PB-NOTIFY-LEG-CONTACTS`
- Map to sector-specific escalation contacts in SOAR

## Sector-Specific Context

### Why This Matters for Legal

Fee-earner workstations, DMS hosts, matter management servers are high-priority targets. Persistence on these systems carries additional risk beyond the generic case:
- Sector-critical systems may have limited or no patching cadence
- Privileged access to sector-specific data or physical systems
- Regulatory notification obligations under: SRA, UK GDPR, ICO

### Regulatory Obligations If This Fires on Legal Infrastructure

| Regulation | Obligation | Timeline |
|-----------|-----------|---------|
| UK GDPR | Notify ICO if personal data involved | 72 hours |
| SRA | Notify relevant authority | See regulation |

## Investigation Guide

Follow the `GEN-PE-001` investigation guide. Additional Legal-specific steps:

1. **Identify system criticality:** Is the affected host a critical Legal system? Who is the business owner?
2. **Assess sector impact:** What Legal operations or data could be affected?
3. **Regulatory triage:** Does this trigger any notification obligations under SRA, UK GDPR, ICO?
4. **Notify sector contacts:** Use the Legal escalation path in SOAR.

## Response Actions

Follow `GEN-PE-001` response actions. Additional:
- [ ] Notify Legal sector security contact (stored in SOAR customer profile)
- [ ] Assess regulatory notification obligations: SRA, UK GDPR, ICO
- [ ] Document sector-specific impact for post-incident report

## References

- Base rule: `GEN-PE-001` — full KQL and investigation guide
- Sector regulatory framework: SRA, UK GDPR, ICO
