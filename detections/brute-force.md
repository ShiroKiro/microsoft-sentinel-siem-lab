# Detection: Repeated Failure Operations

## Description
Detects multiple failed Azure operations from the same caller 
within a 1-hour window. May indicate unauthorized access attempts 
or brute force activity.

## KQL Query
```kql
AzureActivity
| where ActivityStatusValue == "Failure"
| summarize FailureCount = count() by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where FailureCount >= 2
| order by FailureCount desc
```

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Technique | Valid Accounts (T1078) |
| Severity | Medium |

## Analytics Rule
- Rule name: `Repeated Failure Operations Detected`
- Run every: 5 hours
- Lookback: 5 hours
- Threshold: > 0 results

## False Positive Analysis
Authorized administrators performing lab setup or configuration 
changes may trigger this rule. Verify caller identity and 
operation context before escalating.