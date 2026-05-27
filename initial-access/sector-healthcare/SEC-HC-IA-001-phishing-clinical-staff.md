# SEC-HC-IA-001 — Healthcare: Phishing Targeting Clinical Staff

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-HC-IA-001` |
| **MITRE Technique** | T1566.001 — Spearphishing Attachment |
| **Sector** | Healthcare |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 · Defender XDR |
| **Log Source** | `EmailEvents` · `DeviceProcessEvents` (MDE) |
| **Sector Context** | NHS trusts, hospitals, GP practices, community healthcare |

## Description
Healthcare staff are among the most targeted phishing recipients due to time pressure, lack of cybersecurity training, and access to high-value patient data. This rule correlates malicious email delivery with subsequent Office macro execution on clinical workstations, extending the generic GEN-IA-001 with NHS-specific context and regulatory triggers.

**NHS DSPT Requirement 9:** Significant cyber incidents must be reported to NHS England SIRO.

## Microsoft Sentinel KQL
```kql
// SEC-HC-IA-001 | Frequency: 5m | Lookback: 1h
let ClinicalHosts = (_GetWatchlist('ClinicalHosts') | project SearchKey);
let OfficeApps = dynamic(["WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","ONENOTE.EXE"]);
let Shells = dynamic(["cmd.exe","powershell.exe","wscript.exe","mshta.exe","cscript.exe"]);
// Step 1: Office macro execution on clinical host
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where InitiatingProcessFileName in~ (OfficeApps)
| where FileName in~ (Shells)
| where DeviceName in~ (ClinicalHosts)
    or DeviceName has_any ("ward","clinic","theatre","pharmacy","gp","nhs","trust")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
| extend AlertTitle = strcat("Clinical Workstation Phishing Execution: ", DeviceName)
| extend NHSObligation = "Report to NHS England SIRO if clinical data or systems at risk"
```

## Investigation Guide
**Step 1:** Isolate the clinical workstation immediately. Does the user's role mean patient records are exposed?
**Step 2:** Run email source investigation (GEN-IA-001 MDO queries) — scope other NHS recipients.
**Step 3:** Notify CCIO and Data Protection Officer in parallel with technical investigation.
**Step 4:** Assess whether clinical care delivery is affected — notify ward manager if so.

## Response Actions
- [ ] Isolate device — MDE
- [ ] Notify CCIO and DPO
- [ ] Block sending domain in MDO
- [ ] Report to NHS England SIRO if clinical system or patient data involved

## References
- [MITRE T1566.001](https://attack.mitre.org/techniques/T1566/001/) | [NHS DSPT](https://www.dsptoolkit.nhs.uk)
