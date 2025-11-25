## Sentinel
```KQL
//Pulls EDIPI from Syslog and finds the user account associated with it
let timeframe = 1d;
let Users = (
Syslog
| where TimeGenerated >ago(timeframe)
| where SyslogMessage matches regex @"'[^'\s]{10}'"
| extend EDIPI = extract(@"'([^'\s]{10})'", 1, SyslogMessage)
| extend Prefix = strcat(EDIPI, "11700")
| distinct EDIPI, Prefix
);
IdentityInfo
| where TimeGenerated >ago(timeframe)
| extend Employee = substring(EmployeeId, strlen(EmployeeId)-1, 1)
| extend Prefix = substring(EmployeeId, 0, strlen(EmployeeId)-1)
| where Employee matches regex @"^\d$"
| join kind=inner (Users) on Prefix
| summarize count()by AccountName, EmployeeId
```
