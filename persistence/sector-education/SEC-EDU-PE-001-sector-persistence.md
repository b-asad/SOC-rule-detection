# SEC-EDU-PE-001 — Education: Registry Run Key / Account Persistence

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-EDU-PE-001` |
| **MITRE Tactic** | Persistence |
| **Sector** | **Education** |
| **Severity** | See base rule `GEN-PE-001` — apply same severity |
| **Priority** | See base rule `GEN-PE-001` |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | See `GEN-PE-001` |
| **Sector Context** | Student/staff workstations, research systems, VLE servers |
| **Regulatory** | UK GDPR, JISC, Cyber Essentials |

## Description

This rule applies the `GEN-PE-001` detection logic scoped to **Education** infrastructure — restricting detection to hosts and systems specific to this sector using the watchlist and naming patterns below. The full KQL, investigation guide, and response actions from `GEN-PE-001` apply; this file adds the sector-specific host scope, context, and regulatory obligations.

**Deploy this rule in addition to `GEN-PE-001` — not instead of it.**

## Sentinel KQL — Sector-Scoped Variant

```kql
// SEC-EDU-PE-001 | Sector scope applied to GEN-PE-001
// Full query: copy from GEN-PE-001 and add the WHERE clause below
// Sector host filter — add to the base query:
// | where DeviceName has_any ("<EDUCATION-HOST-PATTERNS>")
//     or DeviceName in~ (_GetWatchlist('EducationHosts') | project SearchKey)
// This surfaces Education-specific alerts separately in the Sentinel incidents queue
// and enables sector-specific playbook routing and escalation paths.
```

Alternatively, create a copy of the `GEN-PE-001` Sentinel Analytics Rule with:
- Rule name prefixed `SEC-EDU-PE-001`
- Add sector host filter to the WHERE clause
- Assign sector-specific playbook: `PB-NOTIFY-EDU-CONTACTS`
- Map to sector-specific escalation contacts in SOAR

## Sector-Specific Context

### Why This Matters for Education

Student/staff workstations, research systems, VLE servers are high-priority targets. Persistence on these systems carries additional risk beyond the generic case:
- Sector-critical systems may have limited or no patching cadence
- Privileged access to sector-specific data or physical systems
- Regulatory notification obligations under: UK GDPR, JISC, Cyber Essentials

### Regulatory Obligations If This Fires on Education Infrastructure

| Regulation | Obligation | Timeline |
|-----------|-----------|---------|
| UK GDPR | Notify ICO if personal data involved | 72 hours |
| UK GDPR | Notify relevant authority | See regulation |

## Investigation Guide

Follow the `GEN-PE-001` investigation guide. Additional Education-specific steps:

1. **Identify system criticality:** Is the affected host a critical Education system? Who is the business owner?
2. **Assess sector impact:** What Education operations or data could be affected?
3. **Regulatory triage:** Does this trigger any notification obligations under UK GDPR, JISC, Cyber Essentials?
4. **Notify sector contacts:** Use the Education escalation path in SOAR.

## Response Actions

Follow `GEN-PE-001` response actions. Additional:
- [ ] Notify Education sector security contact (stored in SOAR customer profile)
- [ ] Assess regulatory notification obligations: UK GDPR, JISC, Cyber Essentials
- [ ] Document sector-specific impact for post-incident report

## References

- Base rule: `GEN-PE-001` — full KQL and investigation guide
- Sector regulatory framework: UK GDPR, JISC, Cyber Essentials
