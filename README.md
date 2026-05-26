# 🛡️ MSSP SOC — MITRE ATT&CK Detection Rule Baseline

**Maintained by:** Security Operations Centre (MSSP)  
**Framework:** MITRE ATT&CK® Enterprise v15  
**Microsoft Tools:** Sentinel · Defender XDR · Defender for Endpoint · Defender for Identity · Defender for Office 365 · Defender for Cloud Apps  
**Last Updated:** May 2026 | **Total Rules:** 178 | **Tactics:** 12 | **Sectors:** 4

---

## 📁 Repository Structure

Rules are organised by **Tactic → Sector** so analysts can navigate directly to the relevant attack phase and customer profile.

```
tactics/
├── initial-access/
│   ├── generic/              ← Deploy to ALL customers
│   ├── retail-general/       ← All retail customers
│   ├── retail-food-grocery/  ← Food & grocery specific
│   └── retail-fashion-apparel/ ← Fashion & apparel specific
├── execution/
│   ├── generic/
│   └── ...
├── persistence/
├── privilege-escalation/
├── defense-evasion/
├── credential-access/
├── discovery/
├── lateral-movement/
├── collection/
├── exfiltration/
├── command-and-control/
└── impact/

docs/
├── deployment/               ← Tool-specific deployment guides
│   ├── sentinel-deployment.md
│   ├── defender-xdr-deployment.md
│   ├── defender-endpoint-deployment.md
│   ├── defender-identity-deployment.md
│   ├── defender-office365-deployment.md
│   └── defender-cloud-apps-deployment.md
└── investigation-guides/     ← Tactic-level investigation procedures
    ├── initial-access-guide.md
    ├── credential-access-guide.md
    └── ...
```

---

## 🏷️ Rule ID Convention

```
[SECTOR]-[TACTIC]-[SEQ]
GEN-IA-001    → Generic, Initial Access, rule 001
RG-CA-001     → Retail General, Credential Access, rule 001
RF-IM-001     → Retail Food & Grocery, Impact, rule 001
RA-CO-001     → Retail Fashion & Apparel, Collection, rule 001
```

---

## 🏗️ Sector Profiles

| Sector | ID Prefix | Deploy To | Key Threats |
|--------|-----------|-----------|-------------|
| **Generic** | `GEN` | All customers | Full MITRE ATT&CK baseline |
| **Retail General** | `RG` | All retail | POS malware, Magecart, loyalty fraud |
| **Food & Grocery** | `RF` | Food retailers | ERP compromise, food safety tampering, cold chain |
| **Fashion & Apparel** | `RA` | Fashion brands | IP theft, credential stuffing, brand attacks |

---

## 🛠️ Microsoft Tool Coverage Per Rule

Each rule file contains queries for **all applicable Microsoft tools**:

| Tool | Query Language | Primary Use |
|------|---------------|-------------|
| **Microsoft Sentinel** | KQL (Scheduled Analytics) | SIEM correlation, multi-source detection |
| **Defender XDR** | KQL (Advanced Hunting) | Cross-product hunting, custom detections |
| **Defender for Endpoint** | KQL (MDE tables) | Endpoint process, file, network, registry |
| **Defender for Identity** | MDI Alerts + KQL | AD, Kerberos, lateral movement |
| **Defender for Office 365** | KQL (Email tables) | Phishing, BEC, email-borne threats |
| **Defender for Cloud Apps** | CASB Policies + KQL | Cloud access, data exfiltration, UEBA |

---

## 🚀 Deployment Priority Order

### New Customer Onboarding
1. Deploy all `generic/` rules first — these are the baseline for every customer
2. Add retail sector profile rules based on customer type
3. Validate log sources are connected (see onboarding checklist below)
4. Run rules in **alert-only** mode for 7 days before enabling automated response
5. Review and tune false positives using the FP report template

### Log Source Onboarding Checklist

| Log Source | Sentinel Table | Required For Tactics |
|-----------|---------------|---------------------|
| Entra ID Sign-in Logs | `SigninLogs` | IA, CA, LM |
| Entra ID Audit Logs | `AuditLogs` | PE, PE |
| Defender for Endpoint | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents` | EX, PE, DE, CA, LM, IM |
| Defender for Identity | `IdentityLogonEvents`, `IdentityQueryEvents` | CA, LM, DI |
| Defender for Office 365 | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` | IA, CO |
| Defender for Cloud Apps | `CloudAppEvents` | CO, EF |
| Microsoft 365 UAL | `OfficeActivity` | CO, EF |
| Azure Activity Log | `AzureActivity` | PE, DE |
| Firewall / NSG Flow | `AzureNetworkAnalytics_CL` / `CommonSecurityLog` | C2, EF |
| DNS Logs | `DnsEvents` / `AzureDiagnostics` | C2, EF |

---

## 🔴 Severity & Priority SLA

| Severity | Priority | Response SLA | Escalation |
|----------|----------|-------------|-----------|
| Critical | P1 | **15 minutes** | SOC Manager + Customer contact (phone) |
| High | P2 | **1 hour** | Senior Analyst investigation |
| Medium | P3 | **4 hours** | Analyst triage |
| Low | P4 | **Next business day** | Review and document |

---

## 🤝 Contributing

- **New rule:** Use `.github/ISSUE_TEMPLATE/new-detection-rule.md`
- **False positive:** Use `.github/ISSUE_TEMPLATE/false-positive-report.md`
- **PR checklist:** All PRs must use `.github/pull_request_template.md`
- **Review cadence:** All rules reviewed quarterly; sector rules reviewed after any major retail threat campaign

---

## 📞 Escalation Chain

`L2 Analyst → Senior Analyst / Senior Engineer → SOC Manager → Head of Security Services`

All P1 escalation contacts stored per customer in SOAR platform.
