# Find internet faces devices

#### Note
This only finds things marked by MDE as internet facing, results may not be accurate.

## MDE
```KQL
DeviceInfo
| where Timestamp > ago(1d)
| where IsInternetFacing
| extend Parsed = parse_json(AdditionalFields)
| evaluate bag_unpack(Parsed)
```
