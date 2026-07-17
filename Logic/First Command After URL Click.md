# First Command After URL Click

## MDE
```KQL
//Correlate URL click telemetry with endpoint process execution to identify the first process that launched after the initial click.
let FirstClickTime = toscalar(
    UrlClickEvents
    | summarize arg_min(Timestamp, *)
);
DeviceProcessEvents
| where Timestamp > FirstClickTime
| top 1 by Timestamp asc
| project ProcessCommandLine
```
