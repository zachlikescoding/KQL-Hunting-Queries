# Automatically calculate working hours to find logins outside those hours.

#### Risk
How far outside working hours is suspicious can change from user to user. Working an hour or two outside normal hours may not be suspicious.
All results need to be verified with user or LND to determine suspicious.
Keep in mind timezone changes, UTC vs local time.

## MDE
```KQL
//Query Intent: Calculate user's working hours to find logins outside those hours
let TargetUser = "ENTER_TARGET_USER_HERE";
let TimeFrame = ago(90d);
let UserLogs = materialize(
    SigninLogs
    | where Identity == TargetUser and TimeGenerated >= TimeFrame
    | extend Hour = hourofday(TimeGenerated)
);
//Calculate working hours
let StartTime = toint(toscalar(UserLogs | summarize percentile(Hour, 10)));
let EndTime = toint(toscalar(UserLogs | summarize percentile(Hour, 90)));
//Filter for off-hours
UserLogs
| where Hour < StartTime or Hour >= EndTime
| summarize count()by Hour
| sort by count_
```
