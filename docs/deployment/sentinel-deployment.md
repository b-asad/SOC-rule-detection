# Microsoft Sentinel — Deployment Guide

## Prerequisites

Before deploying any rules confirm:
- [ ] Sentinel workspace provisioned and accessible
- [ ] Required data connectors enabled (run `<table> | take 1` to validate each)
- [ ] Contributor role on the Sentinel workspace
- [ ] Playbooks (Logic Apps) deployed and tested
- [ ] All watchlists created and populated (see table below)

---

## Required Watchlists — Create Before Deploying

| Watchlist Name | Content | Rules |
|---------------|---------|-------|
| `TrustedVPNRanges` | Corporate VPN egress IP CIDRs | GEN-IA-002, GEN-IA-003, GEN-CA-002 |
| `TorExitNodes` | Tor exit node IPs — download from torproject.org | GEN-IA-003, SEC-ENRG-IA-001 |
| `InternalEmailDomains` | All internal email domains inc. subsidiaries | GEN-CO-001, SEC-FS-IA-001 |
| `ApprovedInstallers` | Approved software installer SHA256 hashes | GEN-PE-001 |
| `GEN-IA-001-Exclusions` | Office macro FP exclusion hashes | GEN-IA-001 |
| `POS-Hosts` | POS terminal device names | SEC-RET-CA-001, SEC-RET-EF-001 |
| `TradingNetworkHosts` | Trading platform hostnames | SEC-FS-LM-001 |
| `ClinicalHosts` | EPR, PACS, pharmacy, ward device names | SEC-HC-IM-001, SEC-HC-LM-001 |
| `OTNetworkRanges` | OT/ICS subnet CIDRs | SEC-MFG-LM-001, SEC-ENRG-LM-001 |
| `ITNetworkRanges` | IT subnet CIDRs | SEC-MFG-LM-001 |
| `OTAssets` | OT/SCADA hostnames | SEC-ENRG-IA-001 |
| `EnergySystemHosts` | Energy management system hostnames | SEC-ENRG-CA-001, SEC-ENRG-IM-001 |
| `OTEngineeringHosts` | OT engineering workstation hostnames | SEC-MFG-CA-001 |
| `RestrictedGovSystems` | Restricted/classified government hostnames | SEC-GOV-LM-001 |
| `PrivilegedGovAccounts` | Senior Civil Servant and privileged account UPNs | SEC-GOV-CA-001 |
| `LegalSystemHosts` | DMS, matter management hostnames | SEC-LEG-CA-001, SEC-LEG-IM-001 |
| `EducationCriticalHosts` | SIS, VLE, research system hostnames | SEC-EDU-IM-001 |

---

## Deploying a Scheduled Analytics Rule

1. **Sentinel → Analytics → + Create → Scheduled query rule**
2. **General tab:**
   - Name: `[RULE-ID] — [Rule Name] — [Customer]`
   - Severity: match rule Severity field
   - Status: **Disabled** — keep disabled until tuning complete
3. **Set rule logic:**
   - Paste KQL from the rule file's `## Microsoft Sentinel KQL` section
   - Frequency and Lookback: as documented in the rule header comment
   - Threshold: `Results > 0` unless rule specifies otherwise
4. **Alert enrichment:**
   - Entity mapping: Device → `DeviceName`, Account → `AccountName`, IP → `IPAddress`
   - Custom details: `RuleID`, `MitreTechnique`, `Sector`, `AlertTitle`
5. **Automated response:**
   - Assign the playbook documented in the rule's Playbook field
6. **Review and create** (status remains Disabled)
7. **Validation:** Run with 7-day lookback, review all results for FPs
8. **Enable** after tuning

---

## Required Playbooks — Deploy Before Enabling P1 Rules

| Playbook | Trigger | Action | Customer Approval Required |
|---------|---------|--------|--------------------------|
| `PB-ISOLATE-HOST` | P1 endpoint alert | Isolate MDE device | Yes — written sign-off |
| `PB-REVOKE-SESSION` | P1 identity alert | Revoke Entra ID sessions | Yes — written sign-off |
| `PB-RANSOMWARE-RESPONSE` | GEN-IM-001 / GEN-IM-002 | Isolate + notify + open ticket | Yes — written sign-off |
| `PB-ISOLATE-AND-RESET-CREDENTIALS` | GEN-CA-001 | Isolate + flag accounts for reset | Yes — written sign-off |
| `PB-NOTIFY-CUSTOMER` | All P1 rules | SMS/email customer contacts | Not required |

---

## Phase Deployment Order

### Phase 1 — Deploy First (Zero Tolerance — enable on Day 1)
| Rule | Reason |
|------|--------|
| GEN-IM-001 | Ransomware precursor — zero tolerance |
| GEN-DE-001 | AV disabled — zero tolerance |
| GEN-CA-001 | LSASS dump — zero tolerance |
| GEN-DE-002 | Event log cleared — zero tolerance |
| SEC-HC-IM-001 | Patient safety |
| SEC-ENRG-IA-001 | Critical national infrastructure |

### Phase 2 — Within 7 Days (after watchlist population and validation)
All remaining generic rules (GEN-*) and priority sector rules.

### Phase 3 — After 30 Days (baseline-dependent rules)
GEN-LM-001, GEN-LM-002 — require 30-day NTLM/RDP authentication baseline.

---

## Suppression Policy

All suppressions require:
1. FP documented in `false-positive-report.md` issue
2. Senior Analyst validation
3. SOC Manager written approval
4. Suppression scoped as narrow as possible (by hash or specific path — never by process name)
5. Expiry set — maximum 90 days
6. **Zero Tolerance rules** (GEN-IM-001, GEN-DE-001, GEN-CA-001, GEN-DE-002): CISO approval required, maximum 4-hour suppression window
