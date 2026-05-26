# Microsoft Sentinel — Rule Deployment Guide

## Prerequisites
- Sentinel workspace deployed and connected
- Required data connectors enabled (see onboarding checklist in README)
- Contributor role on the Sentinel workspace

## Deploying a Scheduled Analytics Rule

1. Open **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Fill in the **General** tab:
   - Name: `[RULE-ID] — [Rule Name]` (e.g. `GEN-IA-001 — Office Macro Child Process`)
   - Description: copy from rule file Description section
   - Tactics and techniques: set from rule metadata
   - Severity: match rule Severity field
   - Status: **Disabled** initially — enable after 7-day tuning period
3. **Set rule logic** tab:
   - Paste KQL from the `## Microsoft Sentinel KQL` block
   - Set query scheduling: frequency and lookback from rule settings
   - Alert threshold: `> 0` (unless rule specifies otherwise)
4. **Alert enhancement** tab:
   - Entity mapping: as documented per rule
   - Custom details: add `RuleID`, `MitreTechnique`, `Sector`
5. **Automated response** tab:
   - Assign playbook as documented in rule (e.g. `PB-ISOLATE-HOST`)
6. **Review and create** — save as **Disabled**
7. Run a **manual test** against historical data (set lookback to 7d, run once)
8. Review false positives and apply tuning from rule's tuning guidance
9. **Enable** the rule after tuning validation

## Watchlists Required
Create these Sentinel Watchlists before deploying rules:

| Watchlist Name | Purpose | Rules |
|---------------|---------|-------|
| `TrustedVPNRanges` | VPN egress IP ranges | GEN-IA-002 |
| `TorExitNodes` | Tor exit node IPs | GEN-IA-003 |
| `POS-Hosts` | POS terminal device names | RG-CA-001 |
| `SocialMediaManagers` | UPNs of brand social accounts | RA-IM-001 |
| `ApprovedInstallers` | Approved software installer hashes | GEN-PE-001 |
| `GEN-IA-001-Exclusions` | Office macro FP exclusions | GEN-IA-001 |

## Playbooks Required
Deploy these Logic App playbooks from the SOAR library before enabling P1 rules:

| Playbook | Trigger | Rules |
|---------|---------|-------|
| `PB-ISOLATE-HOST` | Isolate MDE device | GEN-IA-001, GEN-CA-001, GEN-IM-001 |
| `PB-REVOKE-SESSION` | Revoke Entra ID user sessions | GEN-IA-002, GEN-CO-001 |
| `PB-RANSOMWARE-RESPONSE` | Full ransomware IR trigger | GEN-IM-001, GEN-IM-002 |
| `PB-NOTIFY-CUSTOMER` | Send customer alert notification | All P1 rules |

## Rule Naming Convention
`[RULE-ID] — [Rule Name] — [Customer Name]`  
Example: `GEN-IA-001 — Office Macro Child Process — Acme Retail`

## Incident Grouping
For each rule, configure **Alert grouping** to group alerts into incidents by:
- Entity: Device (for endpoint rules), Account (for identity rules)
- Grouping window: 24 hours
- Re-open closed incidents if new alerts match: **Yes**
