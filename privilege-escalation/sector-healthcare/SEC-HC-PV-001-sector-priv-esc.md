# SEC-HC-PV-001 — Healthcare: UAC Bypass on Sector Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-HC-PV-001` |
| **MITRE Tactic** | Privilege Escalation |
| **Sector** | **Healthcare** |
| **Severity** | See base rule `GEN-PV-001` — apply same severity |
| **Priority** | See base rule `GEN-PV-001` |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | See `GEN-PV-001` |
| **Sector Context** | Clinical workstations, EPR servers, PACS hosts |
| **Regulatory** | NHS DSPT, UK GDPR, Caldicott |

## Description

This rule applies the `GEN-PV-001` detection logic scoped to **Healthcare** infrastructure — restricting detection to hosts and systems specific to this sector using the watchlist and naming patterns below. The full KQL, investigation guide, and response actions from `GEN-PV-001` apply; this file adds the sector-specific host scope, context, and regulatory obligations.

**Deploy this rule in addition to `GEN-PV-001` — not instead of it.**

## Sentinel KQL — Sector-Scoped Variant

```kql
// SEC-HC-PV-001 | Sector scope applied to GEN-PV-001
// Full query: copy from GEN-PV-001 and add the WHERE clause below
// Sector host filter — add to the base query:
// | where DeviceName has_any ("<HEALTHCARE-HOST-PATTERNS>")
//     or DeviceName in~ (_GetWatchlist('HealthcareHosts') | project SearchKey)
// This surfaces Healthcare-specific alerts separately in the Sentinel incidents queue
// and enables sector-specific playbook routing and escalation paths.
```

Alternatively, create a copy of the `GEN-PV-001` Sentinel Analytics Rule with:
- Rule name prefixed `SEC-HC-PV-001`
- Add sector host filter to the WHERE clause
- Assign sector-specific playbook: `PB-NOTIFY-HC-CONTACTS`
- Map to sector-specific escalation contacts in SOAR

## Sector-Specific Context

### Why This Matters for Healthcare

Clinical workstations, EPR servers, PACS hosts are high-priority targets. Privilege Escalation on these systems carries additional risk beyond the generic case:
- Sector-critical systems may have limited or no patching cadence
- Privileged access to sector-specific data or physical systems
- Regulatory notification obligations under: NHS DSPT, UK GDPR, Caldicott

### Regulatory Obligations If This Fires on Healthcare Infrastructure

| Regulation | Obligation | Timeline |
|-----------|-----------|---------|
| UK GDPR | Notify ICO if personal data involved | 72 hours |
| NHS DSPT | Notify relevant authority | See regulation |

## Investigation Guide

Follow the `GEN-PV-001` investigation guide. Additional Healthcare-specific steps:

1. **Identify system criticality:** Is the affected host a critical Healthcare system? Who is the business owner?
2. **Assess sector impact:** What Healthcare operations or data could be affected?
3. **Regulatory triage:** Does this trigger any notification obligations under NHS DSPT, UK GDPR, Caldicott?
4. **Notify sector contacts:** Use the Healthcare escalation path in SOAR.

## Response Actions

Follow `GEN-PV-001` response actions. Additional:
- [ ] Notify Healthcare sector security contact (stored in SOAR customer profile)
- [ ] Assess regulatory notification obligations: NHS DSPT, UK GDPR, Caldicott
- [ ] Document sector-specific impact for post-incident report

## References

- Base rule: `GEN-PV-001` — full KQL and investigation guide
- Sector regulatory framework: NHS DSPT, UK GDPR, Caldicott
