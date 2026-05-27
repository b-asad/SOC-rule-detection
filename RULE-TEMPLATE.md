# [RULE-ID] — [Rule Name]

| Field | Value |
|-------|-------|
| **Rule ID** | `[GEN-XX-000 / SEC-[SECTOR]-XX-000]` |
| **MITRE Tactic** | [Tactic Name] |
| **MITRE Technique** | [Txxxx.xxx — Full Technique Name] |
| **Sector** | [Generic | Retail | Healthcare | Financial Services | Government | Education | Manufacturing | Legal | Technology | Energy & Utilities] |
| **Severity** | [Critical | High | Medium | Low] |
| **Priority** | [P1 | P2 | P3 | P4] |
| **MS Tools** | [Sentinel · Defender XDR · MDE · MDI · MDO · MCAS] |
| **Log Source** | [`TableName` (Tool)] |
| **Sector Context** | [Optional: specific systems, environments, regulatory context] |
| **Created** | [Month Year] |
| **Review Date** | [Quarter + Year] |

---

## Description

[Paragraph 1: What does this rule detect? How does the attack technique work?]

[Paragraph 2: Why does this matter? What is the business/operational impact?]

[Paragraph 3 (sector-specific rules): What is the sector-specific context? Which regulatory obligations apply if this fires?]

---

## Microsoft Sentinel KQL

```kql
// ───────────────────────────────────────────────────────────────
// [RULE-ID] | [Rule Name]
// Frequency: Xm | Lookback: Xm | Threshold: > 0
// Entity: [Device/Account/IP] → [FieldName]
// Playbook: [PB-PLAYBOOK-NAME]
// ───────────────────────────────────────────────────────────────
[QUERY]
```

**Sentinel Settings:** Frequency `Xm` · Lookback `Xm` · Threshold `> 0` · Entity: [mapping] · Playbook: `[PB-NAME]`

---

## Defender XDR — Advanced Hunting

```kql
// ───────────────────────────────────────────────────────────────
// [RULE-ID] | Defender XDR Custom Detection
// Run: Every hour | Severity: [X] | Category: [Tactic]
// Entities: [Device/User/URL] → [FieldName]
// ───────────────────────────────────────────────────────────────
[QUERY]
```

---

## Defender for Endpoint

[MDE-specific configuration, Live Response queries, ASR rules, FIM configuration, or advanced features to enable]

---

## Defender for Identity [delete section if not applicable]

[MDI alert names, sensor configuration, correlation with MDI-native alerts]

---

## Defender for Office 365 [delete section if not applicable]

[MDO alert policy configuration, hunting queries using EmailEvents/UrlClickEvents]

---

## Defender for Cloud Apps [delete section if not applicable]

[MCAS policy type, filter configuration, governance actions, anomaly detection policies to enable]

---

## Investigation Guide

### Step 1 — [Step Name] (0–X minutes)

[Numbered actions with rationale. Include embedded KQL queries where relevant.]

### Step 2 — [Step Name] (X–X minutes)

[Numbered actions. Time estimates are cumulative from alert creation.]

### Step 3 — [Step Name] (X–X minutes)

[Continue for as many steps as needed — typically 4–6 steps for P1 rules]

---

## Response Actions

**Immediate (P1 — within 15 minutes)**
- [ ] [Action 1]
- [ ] [Action 2]

**Within 1 Hour**
- [ ] [Action 1]
- [ ] [Action 2]

**Recovery**
- [ ] [Action 1]

**Regulatory (if applicable)**
- [ ] [Regulatory notification action with timeline]

---

## False Positives

| Scenario | Evidence | Mitigation |
|----------|---------|-----------|
| [Legitimate scenario that triggers this rule] | [How to confirm it is a FP] | [How to suppress narrowly] |

---

## Tuning Guidance

[How to adjust the rule for different customer environments without destroying detection capability. Reference watchlist names for all exclusions — never hardcode values.]

---

## References

- [MITRE technique link: https://attack.mitre.org/techniques/Txxxx/]
- [Microsoft documentation link]
- [Regulatory/sector reference if applicable]
