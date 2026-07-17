# Find which non-system account created the most files on devices they RDP'd into

## MDE
```KQL
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where AccountName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where AccountName !endswith "$"
| project LogonTime = Timestamp, AccountName, DeviceName
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | project FileTime = Timestamp, FileAccountName = InitiatingProcessAccountName, DeviceName, FileName
    ) on DeviceName
| where FileTime > LogonTime
| where FileAccountName == AccountName
| summarize FileCount = count() by AccountName
| sort by FileCount desc

//Enrich file hash with Microsoft's threat intelligence.
DeviceFileEvents
| where ActionType == "FileCreated"
| summarize by SHA1
| invoke FileProfile("SHA1", 1000)
```
