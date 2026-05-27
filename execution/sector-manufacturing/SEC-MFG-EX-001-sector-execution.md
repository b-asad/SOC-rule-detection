# SEC-MFG-EX-001 — Manufacturing: PowerShell/WMI Execution on Sector Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-MFG-EX-001` |
| **MITRE Tactic** | Execution |
| **Sector** | **Manufacturing** |
| **Severity** | See base rule `GEN-EX-001` — apply same severity |
| **Priority** | See base rule `GEN-EX-001` |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | See `GEN-EX-001` |
| **Sector Context** | Engineering workstations, OT jump servers, MES/ERP hosts |
| **Regulatory** | NIS2, ISO 27001 |

## Description

This rule applies the `GEN-EX-001` detection logic scoped to **Manufacturing** infrastructure — restricting detection to hosts and systems specific to this sector using the watchlist and naming patterns below. The full KQL, investigation guide, and response actions from `GEN-EX-001` apply; this file adds the sector-specific host scope, context, and regulatory obligations.

**Deploy this rule in addition to `GEN-EX-001` — not instead of it.**

## Sentinel KQL — Sector-Scoped Variant

```kql
// SEC-MFG-EX-001 | Sector scope applied to GEN-EX-001
// Full query: copy from GEN-EX-001 and add the WHERE clause below
// Sector host filter — add to the base query:
// | where DeviceName has_any ("<MANUFACTURING-HOST-PATTERNS>")
//     or DeviceName in~ (_GetWatchlist('ManufacturingHosts') | project SearchKey)
// This surfaces Manufacturing-specific alerts separately in the Sentinel incidents queue
// and enables sector-specific playbook routing and escalation paths.
```

Alternatively, create a copy of the `GEN-EX-001` Sentinel Analytics Rule with:
- Rule name prefixed `SEC-MFG-EX-001`
- Add sector host filter to the WHERE clause
- Assign sector-specific playbook: `PB-NOTIFY-MFG-CONTACTS`
- Map to sector-specific escalation contacts in SOAR

## Sector-Specific Context

### Why This Matters for Manufacturing

Engineering workstations, OT jump servers, MES/ERP hosts are high-priority targets. Execution on these systems carries additional risk beyond the generic case:
- Sector-critical systems may have limited or no patching cadence
- Privileged access to sector-specific data or physical systems
- Regulatory notification obligations under: NIS2, ISO 27001

### Regulatory Obligations If This Fires on Manufacturing Infrastructure

| Regulation | Obligation | Timeline |
|-----------|-----------|---------|
| UK GDPR | Notify ICO if personal data involved | 72 hours |
| NIS2 | Notify relevant authority | See regulation |

## Investigation Guide

Follow the `GEN-EX-001` investigation guide. Additional Manufacturing-specific steps:

1. **Identify system criticality:** Is the affected host a critical Manufacturing system? Who is the business owner?
2. **Assess sector impact:** What Manufacturing operations or data could be affected?
3. **Regulatory triage:** Does this trigger any notification obligations under NIS2, ISO 27001?
4. **Notify sector contacts:** Use the Manufacturing escalation path in SOAR.

## Response Actions

Follow `GEN-EX-001` response actions. Additional:
- [ ] Notify Manufacturing sector security contact (stored in SOAR customer profile)
- [ ] Assess regulatory notification obligations: NIS2, ISO 27001
- [ ] Document sector-specific impact for post-incident report

## References

- Base rule: `GEN-EX-001` — full KQL and investigation guide
- Sector regulatory framework: NIS2, ISO 27001
