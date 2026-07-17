# Shows all the MITRE TTPs per device

#### Note
You can look for specific tcodes as well, helpful during a hunt.

## MDE
```KQL
//Prints TCODES by device
//let ttp = dynamic(["If you have specific Tcodes to look for, add them here and uncomment lines"]);
AlertEvidence
| where TimeGenerated >= ago(90d)
| extend ParsedTTPs = parse_json(AttackTechniques)
| mv-expand ParsedTTPs 
| extend ParsedTTPs = tostring(ParsedTTPs) 
| where isnotempty(ParsedTTPs) and isnotempty(DeviceName) 
//and ParsedTTPs in (ttp) //Uncomment this if you use specific tcodes at the top.
| summarize UniqueTechniques = make_set(ParsedTTPs), TechniqueCount = dcount(ParsedTTPs) by DeviceName 
| where TechniqueCount >= 10 //Adjust amount as needed to scope 
| order by TechniqueCount desc
```
