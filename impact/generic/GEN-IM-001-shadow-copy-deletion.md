# GEN-IM-001 — Inhibit System Recovery: Shadow Copy Deletion

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IM-001` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | T1490 — Inhibit System Recovery |
| **Sector** | **Generic** — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) · Windows Security Event 4688 |
| **Created** | May 2026 |
| **Review Date** | August 2026 |

---

## Description

Detects deletion of Windows Volume Shadow Copies (VSS) using `vssadmin`, `wmic`, `PowerShell`, `bcdedit`, or `wbadmin`. This is one of the most reliable ransomware precursors — virtually every major ransomware family (LockBit, BlackCat/ALPHV, Royal, Clop, Akira, Black Basta) deletes shadow copies immediately before encrypting files to eliminate the fastest recovery option.

This alert typically fires **between 10 and 60 seconds before mass encryption begins**. Treating this as an active ransomware event without waiting for confirmation is the correct response — the cost of a false isolation is negligible compared to the cost of confirmed ransomware.

**Zero tolerance policy: this rule must never be suppressed and its threshold must never be raised above 0.**

---

## Microsoft Sentinel KQL

```kql
// ───────────────────────────────────────────────────────────────
// GEN-IM-001 | Shadow Copy Deletion — Ransomware Precursor
// Frequency: 5m | Lookback: 5m | Threshold: > 0
// POLICY: Never suppress. Never raise threshold.
// Playbook: PB-RANSOMWARE-RESPONSE (auto-isolate enabled)
// ───────────────────────────────────────────────────────────────
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (
    // vssadmin delete shadows
    (FileName =~ "vssadmin.exe"
        and ProcessCommandLine has_any ("delete shadows", "Delete Shadows", "delete shadow"))
    // wmic shadowcopy delete
    or (FileName =~ "wmic.exe"
        and ProcessCommandLine has_any ("shadowcopy delete", "ShadowCopy delete", "Win32_ShadowCopy"))
    // PowerShell — Get-WmiObject or CIM-based deletion
    or (FileName =~ "powershell.exe"
        and ProcessCommandLine has_any (
            "Win32_ShadowCopy", "ShadowCopy", "Delete()", "vssadmin",
            "WMIC shadowcopy", "gwmi Win32_ShadowCopy"
        ))
    // bcdedit — disable recovery environment
    or (FileName =~ "bcdedit.exe"
        and ProcessCommandLine has_any (
            "recoveryenabled no", "bootstatuspolicy ignoreallfailures"
        ))
    // wbadmin — delete backup catalog
    or (FileName =~ "wbadmin.exe"
        and ProcessCommandLine has "delete catalog")
    // diskshadow — scriptable VSS deletion
    or (FileName =~ "diskshadow.exe"
        and ProcessCommandLine has "delete shadows")
)
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    FolderPath,
    SHA256
| extend AlertTitle = strcat("CRITICAL: Shadow Copy Deletion on ", DeviceName, " — Probable Ransomware")
| extend MitreTechnique = "T1490"
| extend Severity = "Critical"
| extend ImmediateAction = "Isolate device NOW. Activate IR-RANSOMWARE-01 playbook."
```

**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0` · Playbook: `PB-RANSOMWARE-RESPONSE` with **auto-isolate enabled** (pre-approved by customer)

---

## Defender XDR — Advanced Hunting

```kql
// ───────────────────────────────────────────────────────────────
// GEN-IM-001 | Shadow Copy Deletion — Defender XDR
// Run: Every hour | Category: Impact | Severity: High
// Response action: Isolate device (auto-enabled for this rule)
// ───────────────────────────────────────────────────────────────
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where (
    (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows","Delete Shadows"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("shadowcopy delete","Win32_ShadowCopy"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Win32_ShadowCopy","ShadowCopy","Delete()","vssadmin"))
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","bootstatuspolicy"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete catalog")
    or (FileName =~ "diskshadow.exe" and ProcessCommandLine has "delete shadows")
)
| project
    Timestamp, DeviceName, DeviceId, AccountName, AccountDomain,
    FileName, ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, InitiatingProcessSHA256, SHA256
| order by Timestamp desc
```

---

## Defender for Endpoint — MDE Queries

**Check blast radius — which other devices ran the same command:**
```kql
// Are multiple devices affected? This determines whether it's isolated or an outbreak
DeviceProcessEvents
| where Timestamp between (ago(2h) .. now())
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows"
| distinct DeviceName, AccountName, Timestamp
| order by Timestamp asc
```

**Check for pre-encryption activity on the device:**
```kql
// Typical ransomware kill chain commands before encryption
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(24h) .. now())
| where ProcessCommandLine has_any (
    "vssadmin", "shadowcopy", "net stop", "sc stop",
    "taskkill", "wbadmin", "bcdedit", "diskshadow",
    "cipher /w", "sdelete", "fsutil usn", "wevtutil cl"
)
| project Timestamp, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```

**Check if encryption has already started:**
```kql
// Mass file modification = encryption in progress
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(30m) .. now())
| where ActionType == "FileModified"
| summarize FileCount = count() by bin(Timestamp, 1m), FolderPath
| where FileCount > 50
| order by FileCount desc
```

**Identify the ransom note — determines the ransomware family:**
```kql
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(1h) .. now())
| where FileName has_any (
    "README", "DECRYPT", "HOW_TO", "ransom", "RECOVER",
    "YOUR_FILES", "RESTORE", "HELP_DECRYPT", "PAYMENT"
)
| project Timestamp, FileName, FolderPath, SHA256
```

**Find patient zero — the first host affected:**
```kql
// Order all hosts by first shadow copy deletion time
DeviceProcessEvents
| where Timestamp >= ago(4h)
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows"
| summarize FirstSeen = min(Timestamp) by DeviceName, AccountName
| order by FirstSeen asc
// The first row is patient zero
```

---

## Investigation Guide

> ⚠️ **This is an active ransomware event. Contain first. Investigate second.**

### Step 1 — Immediate Containment (0–5 minutes)

1. **Isolate the device immediately** — do not wait for confirmation
2. **Alert the entire SOC team** — this is an all-hands event
3. **Notify the SOC Manager** by phone — who notifies the customer CISO
4. **Activate IR-RANSOMWARE-01 playbook** in the SOAR platform
5. Record the time of first alert — this is the start of the incident timeline

### Step 2 — Blast Radius Assessment (5–15 minutes)

Run the "blast radius" query above.

- **1 device:** Isolated incident — still treat as active ransomware
- **2–5 devices:** Active spread — consider emergency network segmentation at the switch level
- **5+ devices:** Outbreak — activate BCP immediately, contact customer operations team

For each affected device: **isolate via MDE** — do not wait for individual investigation.

### Step 3 — Patient Zero Identification (15–30 minutes)

Run the "patient zero" query. The first host where shadow copies were deleted is likely where the attacker first gained access and deployed the ransomware payload. This host is the starting point for root cause analysis.

On patient zero: run the "pre-encryption activity" query to identify the full attack chain.

### Step 4 — Recovery Readiness (30–60 minutes)

Work with the customer IT team to assess backup status:
1. When was the last clean backup taken?
2. Are the backups stored offline or in an immutable location?
3. Are the backups also encrypted? (Ransomware increasingly targets backup systems first)
4. What is the estimated time to restore from backup?

**Critical:** Do NOT connect backup systems to the network while ransomware may still be active. Verify all hosts are isolated first.

### Step 5 — Ransomware Family Identification (parallel activity)

Run the ransom note query. The ransom note filename and content identifies the ransomware family. Submit to:
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- [No More Ransom](https://www.nomoreransom.org/)

Some families have known decryptors available — check before recommending payment.

---

## Response Actions

**Immediate (P1 — within 15 minutes)**
- [ ] **Isolate ALL affected hosts** — MDE portal (bulk isolation possible via Device groups)
- [ ] **Disconnect NAS and network shares** from the network — unplug if necessary
- [ ] **Notify:** SOC Manager → Head of Security Services → Customer CISO (phone)
- [ ] **Activate BCP** — can the customer operate without affected systems?
- [ ] **Do NOT reboot** affected devices — preserve memory for forensic analysis
- [ ] **Do NOT pay the ransom** — advise the customer firmly against payment

**Within 1 Hour**
- [ ] Confirm backup integrity — are backups clean and accessible?
- [ ] Identify patient zero and begin root cause analysis
- [ ] Notify authorities: NCSC (UK) via [report.ncsc.gov.uk](https://report.ncsc.gov.uk)
- [ ] Notify ICO if personal data is involved — 72-hour GDPR clock starts from the point you become aware
- [ ] Preserve all forensic evidence — logs, memory dumps, disk images — before recovery
- [ ] Identify the ransomware family from the ransom note

**Recovery (24–72 hours)**
- [ ] Restore from the last known-clean backup (verify it is clean before connecting to network)
- [ ] Rebuild compromised systems from clean images — do not restore infected images
- [ ] Reset ALL domain account passwords — assume full credential compromise
- [ ] Reset KRBTGT password twice (first reset now, second 24 hours later)
- [ ] Post-incident review within 5 business days — document root cause, timeline, and remediation

---

## False Positives

| Scenario | Evidence | Mitigation |
|----------|---------|-----------|
| Authorised backup software cleaning up old shadow copies | Backup agent process is signed, runs on a predictable schedule | Require CISO approval for any suppression; maximum 4-hour suppression window; confirm backup agent hash |
| IT admin manual disk cleanup including shadows | Admin ran the command manually, confirmed via Live Response session | Even in this case, investigate — confirm with the admin before suppressing |

> **Policy:** This rule must never be suppressed without written approval from the SOC Manager AND the customer CISO. No exceptions.

---

## Tuning Guidance

- Do not tune. Do not raise the threshold. Do not add exclusions.
- Supplement this rule with MDE's native ransomware protection (Controlled Folder Access)
- Add detection for related ransomware preparation: `cipher /w`, `fsutil usn deletejournal`, `wevtutil cl System`, `sdelete`
- Integrate with SOAR to auto-isolate on first match without analyst approval (pre-approved playbook)
- Consider deploying honeypot files (canary files) in file shares — ransomware will encrypt these first and trigger an even earlier alert

---

## References

- [MITRE T1490](https://attack.mitre.org/techniques/T1490/)
- [NCSC: Ransomware, extortion and the cyber crime ecosystem](https://www.ncsc.gov.uk/whitepaper/ransomware-extortion-and-the-cyber-crime-ecosystem)
- [Microsoft: Ransomware response playbook](https://learn.microsoft.com/en-us/security/ransomware/)
- [No More Ransom: Decryptors](https://www.nomoreransom.org/en/decryption-tools.html)
- [ICO: Reporting data breaches](https://ico.org.uk/for-organisations/report-a-breach/)
