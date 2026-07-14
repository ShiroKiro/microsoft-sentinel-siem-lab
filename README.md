# Microsoft Sentinel Cloud SIEM Lab

![Azure](https://img.shields.io/badge/Azure-Microsoft_Sentinel-blue)
![KQL](https://img.shields.io/badge/Language-KQL-green)
![MITRE](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

## Overview
A cloud-native SIEM lab built on Microsoft Sentinel to demonstrate 
SOC analyst skills: threat detection, KQL querying, incident investigation, 
and security monitoring dashboard creation.

This project extends my [Wazuh open-source SIEM lab](https://github.com/ShiroKiro/soc-security-monitoring-lab) 
to enterprise cloud-native SIEM, showing ability to work across 
both self-hosted and cloud security platforms.

**Duration:** July 2026  
**Environment:** Microsoft Azure (North Europe / Sweden Central)  
**Author:** Oleg Tuboltsev

---

## Architecture

**Data Flow:**
Azure Subscription → Log Analytics Workspace (law-soc-lab) → Microsoft Sentinel

**Data Sources:**
- Azure Activity Logs — subscription-level operations monitoring
- Windows Security Events via AMA — endpoint security events from ServerLabVM

**Detection Layer:**
- 4 Analytics Rules with MITRE ATT&CK mapping
- Automated incident creation and assignment

**Components:**
- `law-soc-lab` — Log Analytics Workspace (North Europe)
- `ServerLabVM` — Windows Server 2022 (Sweden Central, deallocated after use)
- `SOC-Lab-Dashboard` — Sentinel Workbook

**[📊 View Lab Architecture Diagram](architecture/lab-diagram.png)**
---

## Detection Scenarios

### 1. Brute Force - Multiple Failed Logons
| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Credential Access |
| MITRE Technique | T1110 Brute Force |
| Data Source | Windows Security Events |
| Event ID | 4625 |

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Account, Computer, IpAddress, bin(TimeGenerated, 1h)
| where FailedLogons >= 3
| order by FailedLogons desc
```

---

### 2. Suspicious Local Account Creation
| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Persistence |
| MITRE Technique | T1136.001 Create Account: Local Account |
| Data Source | Windows Security Events |
| Event ID | 4720 |

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, TargetAccount, Computer, Activity
| order by TimeGenerated desc
```

---

### 3. Suspicious Local Account Deletion
| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Defense Evasion |
| MITRE Technique | T1070 Indicator Removal |
| Data Source | Windows Security Events |
| Event ID | 4726 |

```kql
SecurityEvent
| where EventID == 4726
| project TimeGenerated, Account, TargetAccount, Computer, Activity
| order by TimeGenerated desc
```

---

### 4. Repeated Failure Operations (Azure)
| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Initial Access |
| MITRE Technique | T1078 Valid Accounts |
| Data Source | Azure Activity Logs |

```kql
AzureActivity
| where ActivityStatusValue == "Failure"
| summarize FailureCount = count() by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where FailureCount >= 2
| order by FailureCount desc
```

---

## Incident Investigation Workflow

Full SOC analyst workflow demonstrated on Incident #1:

1. **Triage** — Reviewed severity, tactics, and affected entities
2. **Assignment** — Assigned incident to self, set status Active
3. **Investigation** — Analyzed entities (Account + IP), reviewed timeline
4. **Documentation** — Added findings as incident comment
5. **Closure** — Closed as False Positive with justification

📸 See `/investigations/incident-01.md` for full writeup with screenshots.

---

## SOC Dashboard

Built a monitoring workbook `SOC-Lab-Dashboard` with:
- Failure operations timechart by hour
- Azure Activity event distribution
- Security incident overview

📸 See `/workbook/screenshots/`

---

## What I Learned

- Deploying and configuring Microsoft Sentinel from scratch
- Connecting data sources via Diagnostic Settings and AMA
- Writing KQL detection queries with time-based aggregation
- Creating scheduled Analytics Rules with MITRE ATT&CK mapping
- Performing end-to-end incident investigation workflow
- Building security monitoring dashboards in Workbooks

---

## Connection to Previous Work

This lab is the enterprise continuation of my 
[Wazuh SIEM Lab](https://github.com/ShiroKiro/soc-security-monitoring-lab):

| | Wazuh Lab | Sentinel Lab |
|---|---|---|
| Type | Open-source, self-hosted | Cloud-native, enterprise |
| Data sources | Local agents, Suricata | Azure Activity, Windows AMA |
| Query language | Lucene/Wazuh rules | KQL |
| Alerting | Custom rules | Analytics Rules + MITRE |

## Roadmap / Next Steps

- **Microsoft Defender for Endpoint (EDR) integration** — planned extension to onboard 
  the lab VM into Defender for Endpoint and ingest endpoint telemetry into Sentinel via 
  the Defender XDR connector. Activation is currently pending trial licensing 
  (billing verification requires an EU-issued payment method); will be completed and 
  documented as a follow-up commit.

Together they demonstrate SIEM understanding across both levels.
