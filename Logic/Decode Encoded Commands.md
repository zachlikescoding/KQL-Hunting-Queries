# Decode encoded commands.

#### Note
Currently specifically setup to decode encoded powershell, can be expanded but found issues with other program commands.

## MDE
```KQL
//Decode Commands and filter out null values
DeviceProcessEvents
//| where DeviceName == 'ENTER_DEVICE_NAME_HERE'
| where FileName == 'powershell.exe'
| extend ParsedCommand = parse_command_line(ProcessCommandLine, "windows")
| extend EncodedCommand = tostring(ParsedCommand.[2])
| extend DecodedCommand = base64_decode_tostring(EncodedCommand)
| extend CleanDecodedCommand = replace_regex(DecodedCommand, @"\x00","")
| extend OneLineDecode = replace_regex(base64_decode_tostring(tostring(ParsedCommand.[2])),@"\x00","")
| where isnotempty(OneLineDecode)
| project-reorder OneLineDecode
```
