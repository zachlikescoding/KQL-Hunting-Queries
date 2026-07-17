# First Logon After URL Click

## MDE
```KQL
//Combine a first URL click with a first logon after that click.
let FirstClick = toscalar(
    UrlClickEvents
	//| where AccountUpn == "target_user"
	//| where Url == "target_url"
    | summarize arg_min(Timestamp, *)
);
DeviceLogonEvents
//| where AccountName == "target_user"
| where Timestamp > FirstClick and ActionType == "LogonSuccess"
| summarize FirstLogon = arg_min(Timestamp, *)
```
