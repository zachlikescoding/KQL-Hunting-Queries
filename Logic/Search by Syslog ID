# Search by Syslog ID

## MDE
```KQL
let IDs = dynamic(["111008","111009","302013","302014","609002","710005"]); //Enter your syslog IDs here
let pattern = strcat(@"\b(", strcat_array(IDs, "|"), @"):");
Syslog
| where TimeGenerated >ago(90d)
| extend Matches = extract(pattern, 1, SyslogMessage)
| where isnotempty(Matches)
| summarize count()by Matches
```
