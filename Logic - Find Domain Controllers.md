# Logically find domain controllers for your network

## MDE
```KQL
//Find Domain Controllers 
let DCs = DeviceNetworkEvents 
| where LocalPort == "88" and LocalIPType == "FourToSixMapping" //Kerberos on devices communicating to themselves 
| distinct DeviceId;
```
