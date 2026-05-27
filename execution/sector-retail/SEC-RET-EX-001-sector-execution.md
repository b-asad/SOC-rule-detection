# SEC-RET-EX-001 — Retail: PowerShell/WMI Execution on Sector Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-EX-001` |
| **MITRE Tactic** | Execution |
| **Sector** | **Retail** |
| **Severity** | See base rule `GEN-EX-001` — apply same severity |
| **Priority** | See base rule `GEN-EX-001` |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | See `GEN-EX-001` |
| **Sector Context** | POS terminals, eCommerce hosts, store servers |
| **Regulatory** | PCI DSS, UK GDPR |

## Description

This rule applies the `GEN-EX-001` detection logic scoped to **Retail** infrastructure — restricting detection to hosts and systems specific to this sector using the watchlist and naming patterns below. The full KQL, investigation guide, and response actions from `GEN-EX-001` apply; this file adds the sector-specific host scope, context, and regulatory obligations.

**Deploy this rule in addition to `GEN-EX-001` — not instead of it.**

## Sentinel KQL — Sector-Scoped Variant

```kql
// SEC-RET-EX-001 | Sector scope applied to GEN-EX-001
// Full query: copy from GEN-EX-001 and add the WHERE clause below
// Sector host filter — add to the base query:
// | where DeviceName has_any ("<RETAIL-HOST-PATTERNS>")
//     or DeviceName in~ (_GetWatchlist('RetailHosts') | project SearchKey)
// This surfaces Retail-specific alerts separately in the Sentinel incidents queue
// and enables sector-specific playbook routing and escalation paths.
```

Alternatively, create a copy of the `GEN-EX-001` Sentinel Analytics Rule with:
- Rule name prefixed `SEC-RET-EX-001`
- Add sector host filter to the WHERE clause
- Assign sector-specific playbook: `PB-NOTIFY-RET-CONTACTS`
- Map to sector-specific escalation contacts in SOAR

## Sector-Specific Context

### Why This Matters for Retail

POS terminals, eCommerce hosts, store servers are high-priority targets. Execution on these systems carries additional risk beyond the generic case:
- Sector-critical systems may have limited or no patching cadence
- Privileged access to sector-specific data or physical systems
- Regulatory notification obligations under: PCI DSS, UK GDPR

### Regulatory Obligations If This Fires on Retail Infrastructure

| Regulation | Obligation | Timeline |
|-----------|-----------|---------|
| UK GDPR | Notify ICO if personal data involved | 72 hours |
| PCI DSS | Notify relevant authority | See regulation |

## Investigation Guide

Follow the `GEN-EX-001` investigation guide. Additional Retail-specific steps:

1. **Identify system criticality:** Is the affected host a critical Retail system? Who is the business owner?
2. **Assess sector impact:** What Retail operations or data could be affected?
3. **Regulatory triage:** Does this trigger any notification obligations under PCI DSS, UK GDPR?
4. **Notify sector contacts:** Use the Retail escalation path in SOAR.

## Response Actions

Follow `GEN-EX-001` response actions. Additional:
- [ ] Notify Retail sector security contact (stored in SOAR customer profile)
- [ ] Assess regulatory notification obligations: PCI DSS, UK GDPR
- [ ] Document sector-specific impact for post-incident report

## References

- Base rule: `GEN-EX-001` — full KQL and investigation guide
- Sector regulatory framework: PCI DSS, UK GDPR
