# Detection: Suspicious Local Account Deletion

## Description
Detects deletion of local user accounts on Windows systems.
May indicate attacker removing traces after using a created account.
Often observed after T1136.001 (Create Account) as part of cleanup.

## KQL Query
See `/kql-queries/account-deletion-4726.kql`

```kql
SecurityEvent
| where EventID == 4726
| project TimeGenerated, Account, TargetAccount, Computer, Activity
| order by TimeGenerated desc
```

## MITRE ATT&CK
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1070 Indicator Removal |
| Severity | Medium |

## Analytics Rule
- **Name:** `Suspicious Local Account Deletion`
- **Run every:** 5 hours
- **Lookback:** 5 hours
- **Threshold:** > 0 results

## Correlation with Other Rules
This rule works best in combination with `Suspicious Local Account Creation`:
- Account created (4720) → Account used → Account deleted (4726)
- This sequence strongly indicates malicious activity

## False Positive Analysis
Authorized administrators removing test or temporary accounts may trigger 
this rule. Check if corresponding account creation event (4720) exists.

## Evidence
![Security Events](../screenshots/day3-02-security-events-kql.png)