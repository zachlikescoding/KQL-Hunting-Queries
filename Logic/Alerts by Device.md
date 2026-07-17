# Alerts by Device

## MDE
```KQL
//Alerts for specific device
let Device = 'host.domain.tld';
let TimeFrame = 7d;
AlertEvidence
| where DeviceName =~ Device
| where Timestamp > ago(TimeFrame)
| summarize arg_max(Timestamp, *) by AlertId
| project AlertId
| join kind=inner AlertInfo on AlertId
| extend AlertLink = strcat('https://security.microsoft.com/alerts/', AlertId)
| project-reorder Timestamp, Title, Category, Severity, DetectionSource, AlertLink
| sort by Timestamp desc
```
