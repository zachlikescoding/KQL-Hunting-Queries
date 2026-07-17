# Enrich file hash with Microsoft's threat intelligence

## MDE
```KQL
DeviceFileEvents
| where ActionType == "FileCreated"
| summarize by SHA1
| invoke FileProfile("SHA1", 1000)
```
