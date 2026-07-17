# Find invalid EDIPI masquerade

#### Note
Used on Navy enterprise, may not apply elsewhere

## MDE
```KQL
//Find Invalid EDIPIs
Syslog
| where SyslogMessage matches regex @"'[^'\s]{10}'"
| extend EDIPI = extract(@"'([^'\s]{10})'", 1, SyslogMessage)
| distinct EDIPI
| extend Invalid = not(EDIPI matches regex @"^\d{10}$")
```
