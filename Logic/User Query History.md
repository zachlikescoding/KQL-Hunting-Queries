# Search for query history by user

## Sentinel
```KQL
//See history of commands ran from specific user
LAQueryLogs 
| where AADEmail contains "ENTER_USER_HERE" and QueryText !startswith "set query" 
| distinct QueryText 
```
