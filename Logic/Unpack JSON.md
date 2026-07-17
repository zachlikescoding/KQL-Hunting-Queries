# Logic for unpacking JSON into columns

## MDE
```KQL
//Unpack a json into columns
DeviceInfo //Change table in question here 
| where isnotempty(AdditionalFields) 
| extend Parsed = parse_json(AdditionalFields) 
| evaluate bag_unpack(Parsed)
```
