# SEC-TECH-PE-001 — Technology: CI/CD Pipeline Injection / Supply Chain Compromise

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-TECH-PE-001` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain |
| **Sector** | **Technology** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| **Log Source** | `CloudAppEvents` (MCAS) · `DeviceProcessEvents` (MDE) · GitHub/Azure DevOps audit logs |
| **Sector Context** | Software development firms, SaaS companies, DevOps environments, cloud-native organisations |
| **Created** | May 2026 |

---

## Description

Detects anomalous activity in CI/CD pipelines that may indicate supply chain compromise: unexpected changes to pipeline configuration files (`.github/workflows`, `Jenkinsfile`, `azure-pipelines.yml`), new secrets or environment variables added outside change management, packages with anomalous names (dependency confusion), and pipeline runs triggered by unexpected accounts or branches.

Supply chain attacks targeting CI/CD pipelines (SolarWinds-style) allow attackers to inject malicious code into software products distributed to downstream customers — dramatically multiplying the impact of a single compromise.

---

## Microsoft Sentinel KQL

```kql
// SEC-TECH-PE-001 | Frequency: 5m | Lookback: 15m | Threshold: > 0
// Detection 1: Changes to CI/CD pipeline configuration files
let PipelineFiles = (
    DeviceFileEvents
    | where TimeGenerated >= ago(15m)
    | where FileName has_any (
        "Jenkinsfile",".travis.yml","azure-pipelines.yml",
        "Dockerfile","docker-compose.yml",".circleci",
        "bitbucket-pipelines.yml","cloudbuild.yaml"
    )
    or FolderPath has_any (".github/workflows",".gitlab-ci",".circleci","Jenkinsfile","pipeline")
    | where ActionType in ("FileCreated","FileModified")
    | where InitiatingProcessFileName !in~ ("git","code","devenv.exe","vim","nano","vscode","node")
    | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, AccountName
    | extend DetectionType = "PipelineConfigModification"
);
// Detection 2: Package manager fetching unusual package names (dependency confusion)
let DepConfusion = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(15m)
    | where FileName in~ ("npm","pip","pip3","yarn","nuget","gem","cargo","go")
    | where ProcessCommandLine has_any ("install","add","require","get")
    // Flag packages with internal-looking names — may indicate dependency confusion
    | where ProcessCommandLine has_any (
        "--registry","--index-url","--source",
        "internal","corp","company","private","local"
    )
    | project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
    | extend DetectionType = "DependencyConfusionRisk"
);
PipelineFiles | union DepConfusion
| extend AlertTitle = strcat("CI/CD Supply Chain Risk: ", FileName, " modified on ", DeviceName)
| extend SupplyChainRisk = "If pipeline runs malicious code, all downstream software products may be compromised"
```

---

## Investigation Guide

**Step 1 — Pipeline Configuration Review (< 15 min)**
What change was made to the pipeline file? Was it:
- A new `curl | bash` step downloading from an external URL?
- A new secret/environment variable being exfiltrated?
- A new step that runs an unsigned binary?
- A new trigger that causes the pipeline to run on all commits including external PRs?

**Step 2 — Who Made the Change? (15–30 min)**
Audit the Git commit history and CI/CD platform:
- Was it a legitimate developer (verify with their manager)?
- Was it a service account? Has the service account been compromised?
- Was it triggered by a dependency update PR from an external contributor?

**Step 3 — Pipeline Runs Since the Change (30–60 min)**
Have any pipeline runs occurred since the suspicious change?
If yes: all build artifacts produced in those runs are potentially compromised.

---

## Response Actions
**Immediate**
- [ ] Revert the pipeline configuration change
- [ ] Invalidate all build artifacts produced since the suspicious change
- [ ] Rotate any secrets/tokens that were present in the pipeline environment

**If artifacts distributed to customers**
- [ ] Notify customers to not install/update until clean build is available
- [ ] Issue security advisory
- [ ] Engage legal team for disclosure obligations

## References
- [MITRE T1195.002](https://attack.mitre.org/techniques/T1195/002/)
- [NCSC: Supply chain security guidance](https://www.ncsc.gov.uk/collection/supply-chain-security)
