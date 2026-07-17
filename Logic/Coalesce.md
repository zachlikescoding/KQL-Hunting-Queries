# Coalesce, used to combine similar columns

## MDE
```KQL
//Example 1
DeviceEvents
| extend NormalizedAccount = coalesce(InitiatingProcessAccountName, AccountName, "")
| where NormalizedAccount != ""
| project Timestamp, DeviceName, NormalizedAccount, ActionType

//Example 2
DeviceFileEvents
| extend FileHash = coalesce(SHA256, SHA1, MD5)
| where isnotempty(FileHash)
| project Timestamp, DeviceName, FileName, FileHash
```
