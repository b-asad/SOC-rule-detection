# [RULE-ID] — [Rule Name]

| Field | Value |
|-------|-------|
| Rule ID | [GEN-XX-000 / RG-XX-000 / RF-XX-000 / RA-XX-000] |
| Tactic | [MITRE Tactic] |
| Technique | [T1xxx.xxx — Full Technique Name] |
| Sector | [Generic / Retail General / Food & Grocery / Fashion & Apparel] |
| Severity | [Critical / High / Medium / Low] |
| Priority | [P1 / P2 / P3 / P4] |
| MS Tools | [Sentinel · Defender XDR · MDE · MDI · MDO · MCAS] |
| Log Source | [`TableName` (Tool)] |
| Retail Context | [Optional: specific retail scenario] |
| Created | [Month Year] |
| Review Date | [Quarter + Year] |

## Description
[2–3 paragraphs: what it detects, why it matters, sector-specific risk]

---

## Microsoft Sentinel KQL
```kql
// [RULE-ID] | Frequency: Xm | Lookback: Xm
[QUERY]
```
**Sentinel Settings:** Frequency `Xm` · Lookback `Xm` · Threshold `> 0` · Entity: [Device/Account] · Playbook: `[PLAYBOOK-NAME]`

---

## Defender XDR — Advanced Hunting
```kql
// [RULE-ID] | Run: Every hour
[QUERY]
```
**Custom Detection:** Severity `[X]` · Category `[Tactic]` · Entities: `[Device/User/URL]`

---

## Defender for Endpoint
[MDE-specific configuration, Live Response queries, or ASR rules]

---

## Defender for Identity [if applicable]
[MDI alert name and configuration]

---

## Defender for Office 365 [if applicable]
[MDO alert policy or hunting query]

---

## Defender for Cloud Apps [if applicable]
[MCAS policy or hunting query]

---

## Investigation Guide

**Step 1 — [Name] (< X min)**
[Steps with embedded KQL]

**Step 2 — [Name] (X–X min)**
[Steps with embedded KQL]

---

## Response Actions
**Immediate:**
- [ ] Action 1

**Short-term:**
- [ ] Action 1

**Recovery:**
- [ ] Action 1

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| [Scenario] | [Mitigation] |

## Tuning Guidance
[How to adjust per customer]

## References
- [MITRE link]
- [Microsoft documentation link]
