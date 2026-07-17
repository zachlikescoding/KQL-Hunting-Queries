# Devices with connections to Tor Exit nodes

####  Source
https://firewalliplists.gypthecat.com/lists/kusto/kusto-tor-exit-historic.json.zip

## MDE
```KQL
//Devices with connections to Tor Exit nodes
let TorExitNodesHistoric = externaldata(IP:string, ActiveDates:string, Source:string) ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-tor-exit-historic.json.zip'] with(format="multijson"); 
TorExitNodesHistoric 
| extend ActiveDates = split(ActiveDates, ',') 
| extend Country = tostring(geo_info_from_ip_address(IP)['country'])
| summarize ActiveDays = array_length(make_set(ActiveDates)) by Country,IP,Source
| join kind=inner (DeviceNetworkEvents) on $left.IP == $right.RemoteIP
| where TimeGenerated >ago(7d)
| where ActionType !in~ ("ConnectionAttempt")
| summarize by Source,DeviceName,TOR_Exit_Node= LocalIP,Country,ActiveDays,RemoteUrl, InitiatingProcessAccountName, InitiatingProcessVersionInfoProductName, ActionType
| order by ActiveDays
```
