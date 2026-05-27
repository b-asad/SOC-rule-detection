# 🛡️ MSSP SOC — MITRE ATT&CK Detection Rule Baseline

> **Maintained by:** Security Operations Centre | **Version:** 3.0 | **Updated:** May 2026

---

## Overview

This repository contains the full MSSP SOC detection rule baseline, covering **MITRE ATT&CK® Enterprise v15** across **12 tactics**, **10 industry sectors**, and **6 Microsoft security tools**. Every rule is production-ready with copy-paste KQL, step-by-step investigation guides, sector-specific context, and response checklists.

---

## 🛠️ Microsoft Tool Coverage

Every rule contains queries and configuration for all applicable tools:

| Tool | Purpose | Primary Tables |
|------|---------|---------------|
| **Microsoft Sentinel** | SIEM — correlation, scheduled analytics | `DeviceProcessEvents`, `SigninLogs`, `OfficeActivity`, `CommonSecurityLog` |
| **Defender XDR** | XDR — Advanced Hunting, cross-product | All Defender hunting tables |
| **Defender for Endpoint (MDE)** | Endpoint — process, file, registry, network | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceEvents`, `DeviceLogonEvents` |
| **Defender for Identity (MDI)** | Identity — AD, Kerberos, lateral movement | `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` |
| **Defender for Office 365 (MDO)** | Email — phishing, BEC, attachments | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents` |
| **Defender for Cloud Apps (MCAS)** | CASB — cloud access, UEBA, DLP | `CloudAppEvents` |

---

## 🏗️ Sector Profiles

| Sector | Prefix | Key Threats | Regulatory Framework |
|--------|--------|------------|---------------------|
| **Generic** | `GEN` | All customers — full MITRE baseline | All applicable |
| **Retail** | `SEC-RET` | POS malware, Magecart, loyalty fraud, supply chain | PCI DSS, UK GDPR |
| **Healthcare** | `SEC-HC` | Patient data theft, ransomware, medical device abuse, insider threat | NHS DSP Toolkit, CQC, UK GDPR |
| **Financial Services** | `SEC-FS` | BEC/fraud, trading system abuse, SWIFT fraud, insider threat | FCA, PRA, DORA, PCI DSS |
| **Government** | `SEC-GOV` | Nation-state APT, espionage, supply chain, credential theft | GovAssure, Cyber Essentials+, NCSC CAF |
| **Education** | `SEC-EDU` | Ransomware, student data theft, research IP theft, phishing | UK GDPR, Cyber Essentials |
| **Manufacturing** | `SEC-MFG` | OT/ICS targeting, IP theft, ransomware, supply chain | NIS2, ISO 27001 |
| **Legal** | `SEC-LEG` | Client data exfiltration, BEC invoice fraud, privilege abuse | SRA, ICO, UK GDPR |
| **Technology** | `SEC-TECH` | Code/IP theft, supply chain compromise, cloud misconfig, insider | SOC 2, ISO 27001 |
| **Energy & Utilities** | `SEC-ENRG` | OT/SCADA attacks, nation-state, physical impact threats | NIS2, NCSC CAF |

---

## 📁 Repository Structure

```
tactics/
├── initial-access/
│   ├── generic/                    ← Deploy to ALL customers
│   ├── sector-retail/              ← Retail-specific initial access
│   ├── sector-healthcare/          ← Healthcare-specific
│   ├── sector-financial-services/
│   ├── sector-government/
│   ├── sector-education/
│   ├── sector-manufacturing/
│   ├── sector-legal/
│   ├── sector-technology/
│   └── sector-energy-utilities/
├── execution/
│   └── [same sector subfolders]
├── persistence/ ...
├── privilege-escalation/ ...
├── defense-evasion/ ...
├── credential-access/ ...
├── discovery/ ...
├── lateral-movement/ ...
├── collection/ ...
├── exfiltration/ ...
├── command-and-control/ ...
└── impact/ ...

docs/
├── deployment/                     ← Per-tool deployment guides
│   ├── sentinel-deployment.md
│   ├── defender-xdr-deployment.md
│   ├── defender-endpoint-deployment.md
│   ├── defender-identity-deployment.md
│   ├── defender-office365-deployment.md
│   └── defender-cloud-apps-deployment.md
├── investigation-guides/           ← Per-tactic investigation procedures
│   ├── initial-access-guide.md
│   ├── credential-access-guide.md
│   ├── lateral-movement-guide.md
│   ├── impact-guide.md
│   └── ...
├── sector-profiles/                ← Sector threat landscape & onboarding
│   ├── retail-profile.md
│   ├── healthcare-profile.md
│   ├── financial-services-profile.md
│   └── ...
└── playbooks/                      ← SOAR playbook references
    ├── PB-ISOLATE-HOST.md
    ├── PB-RANSOMWARE-RESPONSE.md
    └── ...
```

---

## 📋 Rule ID Convention

```
[SCOPE]-[TACTIC]-[SEQ]

GEN-IA-001       → Generic,              Initial Access,  rule 001
SEC-RET-CA-001   → Retail sector,        Credential Access
SEC-HC-IM-001    → Healthcare sector,    Impact
SEC-FS-CO-001    → Financial Services,   Collection
SEC-GOV-LM-001   → Government,          Lateral Movement
SEC-EDU-EX-001   → Education,           Execution
SEC-MFG-DE-001   → Manufacturing,       Defense Evasion
SEC-LEG-EF-001   → Legal,               Exfiltration
SEC-TECH-PE-001  → Technology,          Persistence
SEC-ENRG-IA-001  → Energy & Utilities,  Initial Access
```

---

## 🔴 Severity & Priority SLA

| Severity | Priority | SOC Response SLA | Escalation Path |
|----------|----------|-----------------|----------------|
| **Critical** | P1 | **15 minutes** | L2 → Senior Analyst → SOC Manager → Head of Security Services → Customer CISO (phone) |
| **High** | P2 | **1 hour** | L2 → Senior Analyst → SOC Manager |
| **Medium** | P3 | **4 hours** | L2 → Senior Analyst |
| **Low** | P4 | **Next business day** | L2 review |

---

## 🚀 Customer Onboarding — Deployment Order

1. **Connect log sources** — validate all required tables are populated (see sector profile doc)
2. **Deploy Generic rules** — all customers receive the full generic baseline
3. **Deploy Sector rules** — add the relevant sector profile on top
4. **Run in Alert-only mode** — 7-day observation before automated response
5. **Tune false positives** — use FP report template, document all suppressions
6. **Enable automated response playbooks** — P1 rules only, after customer approval
7. **Quarterly review** — review all rules, update tuning, remove stale exclusions

---

## ⚖️ Regulatory Quick Reference

| Regulation | Sectors | Key Requirement |
|-----------|---------|----------------|
| **UK GDPR / GDPR** | All | 72h breach notification to ICO |
| **PCI DSS v4.0** | Retail, Financial | 24h card brand notification |
| **NHS DSP Toolkit** | Healthcare | Mandatory data security standards |
| **FCA SYSC** | Financial Services | Operational resilience requirements |
| **DORA** | Financial Services | ICT incident reporting within 4h |
| **NIS2** | Manufacturing, Energy | 24h initial incident report |
| **GovAssure** | Government | Annual assurance assessment |
| **SRA Code** | Legal | Client data protection obligations |
| **NCSC CAF** | Government, Energy | Cyber Assessment Framework |

---

## 🤝 Contributing

| Action | Template |
|--------|---------|
| Request a new rule | `.github/ISSUE_TEMPLATE/new-detection-rule.md` |
| Report a false positive | `.github/ISSUE_TEMPLATE/false-positive-report.md` |
| Submit a rule update | `.github/pull_request_template.md` |

**Review cadence:** All rules reviewed quarterly. Sector rules reviewed after major threat campaigns targeting that sector.

---

## 📞 SOC Escalation Chain

```
Alert fires
  └─► L2 Security Analyst (triage & initial investigation)
        └─► Senior Analyst / Senior SOC Engineer (P1/P2 escalation)
              └─► SOC Manager (P1 — 30 min, customer notification)
                    └─► Head of Security Services / CISO (P1 — major incidents)
```

All customer escalation contacts stored in SOAR platform per customer profile.
