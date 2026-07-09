# Incident #1 - Repeated Failure Operations Detected

## Overview
| Field | Value |
|-------|-------|
| Incident ID | #1 |
| Title | Repeated Failure Operations Detected |
| Severity | Medium |
| Status | Closed |
| Classification | False Positive |
| Owner | Oleg Tuboltsev |
| Created | 08.07.2026 18:06 UTC |
| Closed | 08.07.2026 18:13 UTC |

## Alert Details
- **Analytics Rule:** Repeated Failure Operations Detected
- **MITRE Tactic:** Initial Access
- **MITRE Technique:** T1078 - Valid Accounts
- **Data Source:** Azure Activity Logs

## Affected Entities
| Entity | Value |
|--------|-------|
| Account | barmus20128@gmail.com |
| IP Address | 45.85.235.78 |
| Resource Group | RG-SOC-LAB |

## Timeline
| Time (UTC) | Event |
|------------|-------|
| 18:06 | Incident created automatically by Analytics Rule |
| 18:09 | Incident assigned to Oleg Tuboltsev, status set to Active |
| 18:10 | Investigation started - reviewed entities and timeline |
| 18:13 | Incident closed as False Positive |

## Investigation Findings

**What happened:**
3 failed operations of type `MICROSOFT.COMPUTE/LOCATIONS/PLACEMENTRECOMMENDATIONS/GENERATE/ACTION` 
were detected from the same caller within a 1-hour window, triggering the analytics rule.

**Analysis:**
- Caller identity confirmed as authorized administrator (lab owner)
- IP address 45.85.235.78 matches known lab workstation
- Operations occurred during Azure lab setup activities
- Failed operations were caused by VM size quota limitations in North Europe region
- No indicators of unauthorized access or lateral movement detected

**Verdict:** False Positive — activity matches authorized administrator 
actions during lab environment setup.

**Recommendation:** 
Add exclusion for lab setup operations or raise threshold to reduce 
false positive rate in production environment.

## Screenshots
- `incident-created.png` — Incident automatically created by Sentinel
- `incident-investigation.png` — Investigation workflow
- `incident-closed.png` — Incident closed with classification

## Lessons Learned
- Analytics rules need tuning to reduce false positives in lab environments
- Entity mapping (Account + IP) provides quick context for triage
- Azure quota errors generate failure events that can trigger detection rules