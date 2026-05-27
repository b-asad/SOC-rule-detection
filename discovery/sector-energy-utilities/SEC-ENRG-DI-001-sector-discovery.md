# SEC-ENRG-DI-001 — Energy & Utilities: Network Scanning on Sector Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-ENRG-DI-001` |
| **MITRE Tactic** | Discovery |
| **Sector** | **Energy & Utilities** |
| **Severity** | See base rule `GEN-DI-001` — apply same severity |
| **Priority** | See base rule `GEN-DI-001` |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | See `GEN-DI-001` |
| **Sector Context** | OT engineering workstations, energy management hosts, control room PCs |
| **Regulatory** | NIS2, NCSC CAF, Ofgem/Ofwat |

## Description

This rule applies the `GEN-DI-001` detection logic scoped to **Energy & Utilities** infrastructure — restricting detection to hosts and systems specific to this sector using the watchlist and naming patterns below. The full KQL, investigation guide, and response actions from `GEN-DI-001` apply; this file adds the sector-specific host scope, context, and regulatory obligations.

**Deploy this rule in addition to `GEN-DI-001` — not instead of it.**

## Sentinel KQL — Sector-Scoped Variant

```kql
// SEC-ENRG-DI-001 | Sector scope applied to GEN-DI-001
// Full query: copy from GEN-DI-001 and add the WHERE clause below
// Sector host filter — add to the base query:
// | where DeviceName has_any ("<ENERGY-&-UTILITIES-HOST-PATTERNS>")
//     or DeviceName in~ (_GetWatchlist('Energy&UtilitiesHosts') | project SearchKey)
// This surfaces Energy & Utilities-specific alerts separately in the Sentinel incidents queue
// and enables sector-specific playbook routing and escalation paths.
```

Alternatively, create a copy of the `GEN-DI-001` Sentinel Analytics Rule with:
- Rule name prefixed `SEC-ENRG-DI-001`
- Add sector host filter to the WHERE clause
- Assign sector-specific playbook: `PB-NOTIFY-ENRG-CONTACTS`
- Map to sector-specific escalation contacts in SOAR

## Sector-Specific Context

### Why This Matters for Energy & Utilities

OT engineering workstations, energy management hosts, control room PCs are high-priority targets. Discovery on these systems carries additional risk beyond the generic case:
- Sector-critical systems may have limited or no patching cadence
- Privileged access to sector-specific data or physical systems
- Regulatory notification obligations under: NIS2, NCSC CAF, Ofgem/Ofwat

### Regulatory Obligations If This Fires on Energy & Utilities Infrastructure

| Regulation | Obligation | Timeline |
|-----------|-----------|---------|
| UK GDPR | Notify ICO if personal data involved | 72 hours |
| NIS2 | Notify relevant authority | See regulation |

## Investigation Guide

Follow the `GEN-DI-001` investigation guide. Additional Energy & Utilities-specific steps:

1. **Identify system criticality:** Is the affected host a critical Energy & Utilities system? Who is the business owner?
2. **Assess sector impact:** What Energy & Utilities operations or data could be affected?
3. **Regulatory triage:** Does this trigger any notification obligations under NIS2, NCSC CAF, Ofgem/Ofwat?
4. **Notify sector contacts:** Use the Energy & Utilities escalation path in SOAR.

## Response Actions

Follow `GEN-DI-001` response actions. Additional:
- [ ] Notify Energy & Utilities sector security contact (stored in SOAR customer profile)
- [ ] Assess regulatory notification obligations: NIS2, NCSC CAF, Ofgem/Ofwat
- [ ] Document sector-specific impact for post-incident report

## References

- Base rule: `GEN-DI-001` — full KQL and investigation guide
- Sector regulatory framework: NIS2, NCSC CAF, Ofgem/Ofwat
