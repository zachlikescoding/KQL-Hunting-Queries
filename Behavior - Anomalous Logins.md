# Baseline logins and find anomalies

## MDE
```KQL
//Find login anomalies.
//Make an array of login counts. Adjust time frames as needed.
let StartTime = ago(90d);
let EndTime = now();
let TimeStep = 1d;
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where AccountName contains "target_user" //adjust "target_user"
//Make an array of login counts
| make-series DailyLogons=count()
	on Timestamp
	from StartTime
	to EndTime
	step TimeStep
	by AccountName
//Built-in function "series_decompose_anomalies" will baseline series and score anomalies
| extend (Anomalies, Score, Baseline) =
	series_decompose_anomalies(DailyLogons)
//Break out series into readable separate events we can use
| mv-expand Timestamp, DailyLogons, Anomalies, Score
//Only show anomalous events
//| where Anomalies != 0
| project Timestamp, AccountName, DailyLogons, Score
//Convert Score from dynamic to real number to be able to sort
| extend Score = toreal(Score)
| sort by Score desc
```

## Sentinel
```KQL
//Sentinel SigninLogs version
let StartTime = ago(90d);
let EndTime = now();
let TimeStep = 1d;
SigninLogs
| where TimeGenerated > ago(90d)
| where Identity contains "target_user" //adjust "target_user"
//Make an array of login counts
| make-series DailyLogons=count()
	on TimeGenerated
	from StartTime
	to EndTime
	step TimeStep
	by Identity
//Built-in function "series_decompose_anomalies" will baseline series and score anomalies
| extend (Anomalies, Score, Baseline) =
    series_decompose_anomalies(DailyLogons)
| mv-expand TimeGenerated, DailyLogons, Anomalies, Score
| project TimeGenerated, Identity, DailyLogons, Score
//Convert Score from dynamic to real number to be able to sort
| extend DailyLogons = toreal(DailyLogons)
| sort by DailyLogons desc
```
