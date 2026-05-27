# SEC-HC-EF-001 — Healthcare: Patient / Medical Data Upload to External Service

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-HC-EF-001` |
| **MITRE Tactic** | Exfiltration |
| **MITRE Technique** | T1567 — Exfiltration to Cloud Service |
| **Sector** | **Healthcare** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| **Log Source** | `CommonSecurityLog` (Firewall) · `CloudAppEvents` (MCAS) · `DeviceNetworkEvents` (MDE) |
| **Sector Context** | NHS trusts, private hospitals, GP practices, community health, clinical research |
| **Created** | May 2026 |

---

## Description

Upload of patient or clinical data to personal cloud storage, file transfer services, or unapproved external platforms. Under the Caldicott Principles and NHS DSPT, patient data must not leave approved clinical systems without explicit governance approval. A confirmed breach is reportable to the ICO (UK GDPR 72h), NHS England SIRO, and may require patient notification.

Healthcare data is the highest-value personal data on the dark web — it commands 10–40x the price of financial data. Insider threat (departing clinical staff, contractors) and compromised accounts are the primary vectors.

---

## Microsoft Sentinel KQL

```kql
// SEC-HC-EF-001 | Frequency: 15m | Lookback: 1h
let PersonalCloud = dynamic([
    "dropbox.com","wetransfer.com","drive.google.com","mega.nz",
    "box.com","mediafire.com","sendspace.com","onedrive.live.com",
    "gofile.io","transfer.sh","icloud.com","files.fm"
]);
let ClinicalFiles = dynamic([".hl7",".fhir",".cda",".xml",".csv",".xlsx",".pdf",".zip"]);
// Detection 1: Upload from clinical network to personal cloud
let NetworkUpload = (
    CommonSecurityLog
    | where TimeGenerated >= ago(1h)
    | where DeviceAction !in ("deny","block","drop")
    | where DestinationHostName has_any (PersonalCloud)
    | where SentBytes > 1000000  // > 1MB
    | project TimeGenerated, SourceIP, DeviceName, DestinationHostName, SentBytes
    | extend DetectionType = "PersonalCloudUpload"
);
// Detection 2: Browser-based upload of clinical file types from clinical host
let BrowserUpload = (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(1h)
    | where RemoteUrl has_any (PersonalCloud)
    | where BytesSent > 500000
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
    | project TimeGenerated, DeviceName, AccountName, RemoteUrl, BytesSent, InitiatingProcessFileName
    | extend DetectionType = "BrowserUploadToCloud"
);
NetworkUpload | union BrowserUpload
| extend AlertTitle = strcat("Clinical Data Exfiltration: Upload to ", DestinationHostName)
| extend CaldicottBreach = "Potential breach of Caldicott Principles 2, 3, and 5"
| extend NHSObligation = "Report to NHS England SIRO and ICO (72h) if patient data confirmed"
```

---

## Defender for Cloud Apps — Anomaly Detection

Enable MCAS anomaly policy: **Unusual file download** — set sensitivity High for healthcare tenants.

```kql
// MCAS: Files labelled as clinical or confidential shared externally
CloudAppEvents
| where Timestamp >= ago(24h)
| where ActionType in ("FileUploaded","FileShared")
| where AppName has_any ("Dropbox","Google Drive","Box","WeTransfer","OneDrive Personal")
| where tostring(AdditionalFields.SensitivityLabelName) has_any ("Clinical","Patient","Confidential","NHS","Medical")
| project Timestamp, AccountUpn, AppName, tostring(AdditionalFields.FileName), IPAddress, CountryCode
```

---

## Defender for Endpoint — Data Staging Investigation

```kql
// Was patient data staged locally before upload?
DeviceFileEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where Timestamp between (ago(4h) .. now())
| where FileName has_any (".csv",".xlsx",".zip",".hl7",".pdf")
| where FolderPath has_any ("Desktop","Downloads","Temp","AppData","Documents")
| project Timestamp, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

```kql
// What EPR or clinical application did the files originate from?
DeviceProcessEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where Timestamp between (ago(4h) .. now())
| where FileName has_any ("RiO","SystmOne","EMIS","Cerner","Epic","Meditech","PACS","PharmacySystem")
    or ProcessCommandLine has_any ("patient","clinical","nhs","record","export")
| project Timestamp, FileName, ProcessCommandLine, AccountName
```

---

## Investigation Guide

**Step 1 — Clinical data confirmation (0–10 min)**
What files were uploaded? Are they patient-identifiable (name, NHS number, DOB, diagnosis)?
Contact the user's clinical line manager (not the user) — was there a legitimate reason for this transfer?

**Step 2 — Caldicott assessment (10–25 min)**
Apply the Caldicott Test to the disclosure:
1. Is there a legitimate clinical purpose? (If no: breach)
2. Was the minimum necessary data used? (If no: breach)
3. Did the patient consent or would they expect this use? (If no: likely breach)

Notify the **Caldicott Guardian** immediately if any answer is no.

**Step 3 — Scope of disclosure (25–40 min)**
How many patient records were in the uploaded files?
Run the staging investigation query — was data aggregated from multiple sources?

**Step 4 — Regulatory timeline (40–60 min)**
UK GDPR Article 33: 72-hour clock starts from the point the organisation became aware.
NHS DSPT Requirement 9.6: Report to NHS England Data Security Centre.

---

## Response Actions

**Immediate**
- [ ] Block personal cloud storage at network egress for clinical network
- [ ] Suspend the user's clinical system access pending investigation
- [ ] Notify Caldicott Guardian and Data Protection Officer

**Regulatory (time-critical)**
- [ ] Notify ICO within 72h: [ico.org.uk/report-a-breach](https://ico.org.uk/for-organisations/report-a-breach/)
- [ ] Notify NHS England SIRO and complete DSPT incident report
- [ ] Assess patient notification requirement (UK GDPR Article 34)
- [ ] For NHS trust: notify NHS England Data Security Centre

**HR/Legal**
- [ ] Preserve evidence for HR disciplinary process or law enforcement
- [ ] Engage legal counsel if patient data traded commercially

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Approved research data transfer to academic partner | Requires signed data sharing agreement and IG approval — add approved partner domains to allowlist |
| Clinical audit team uploading de-identified data | Verify data is genuinely de-identified per ICO standard; add audit team workflow to approved list |

## References
- [MITRE T1567](https://attack.mitre.org/techniques/T1567/)
- [NHS: Caldicott Principles](https://www.gov.uk/government/publications/the-caldicott-principles)
- [NHS DSPT](https://www.dsptoolkit.nhs.uk)
- [ICO: Healthcare sector guidance](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/sector-guidance/health/)
