# User Entity Behavior Analytic query to find unusual user activity.

## MDE
```KQL
let LookbackPeriod = 30d;
let TargetUser = "ENTER_USER_HERE"; // Enter UPN, Email, or partial Name (Case-Insensitive)
//PRE-FILTER BASE TABLES 
let TargetUserBA = BehaviorAnalytics
    | where TimeGenerated > ago(LookbackPeriod)
    | where UserPrincipalName has TargetUser or UserName has TargetUser;
let TargetSigninLogs = SigninLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | extend JoinId = tolower(Id); // Force lowercase for reliable joining
let TargetAuditLogs = AuditLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | extend JoinId = tolower(Id);
let critical = dynamic(['9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', '158c047a-c907-4556-b7ef-446551a6b5f7', '62e90394-69f5-4237-9190-012177145e10', 'd29b2b05-8046-44ba-8758-1e26182fcf32', '729827e3-9c14-49f7-bb1b-9608f156bbb8', '966707d0-3269-4727-9be2-8c3a10f19b9d', '194ae4cb-b126-40b2-bd5b-6091b380977d', 'fe930be7-5e62-47db-91af-98c3a49a38b1']);
let high = dynamic(['cf1c38e5-3621-4004-a7cb-879624dced7c', '7495fdc4-34c4-4d15-a289-98788ce399fd', 'aaf43236-0c0d-4d5f-883a-6955382ac081', '3edaf663-341e-4475-9f94-5c398ef6c070', '7698a772-787b-4ac8-901f-60d6b08affd2', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '9f06204d-73c1-4d4c-880a-6edb90606fd8', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'be2f45a1-457d-42af-a067-6ec1fa63bc45', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'e8611ab8-c189-46e8-94e1-60213ab1f814']);
//ANOMALY SUB-QUERIES (Left-joins & Case-Insensitive Matching)
let AnomalousSigninActivity = TargetUserBA
    | where ActionType == "Sign-in"
    | where tostring(UsersInsights.NewAccount) =~ "True" 
       or tostring(UsersInsights.DormantAccount) =~ "True"
       or tostring(ActivityInsights.FirstTimeUserAccessedResource) =~ "True"
       or tostring(ActivityInsights.FirstTimeUserUsedApp) =~ "True"
    | extend JoinBAId = tolower(SourceRecordId)
    | join kind=leftouter (TargetSigninLogs) on $left.JoinBAId == $right.JoinId
    | extend
        AnomalyName = "Anomalous Successful Logon",
        Tactic = "Persistence", Technique = "Valid Accounts", SubTechnique = "",
        Description = "Sign-in behavior tracked by UEBA matching baseline indicators."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["Evidence"]=ActivityInsights, ResourceDisplayName, AppDisplayName, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority; 
let AnomalousRoleAssignment = TargetAuditLogs
    | where OperationName == "Add member to role"
    | mv-expand TargetResources
    | extend RoleId = tostring(TargetResources.modifiedProperties[0].newValue)
    | extend RoleName = tostring(TargetResources.modifiedProperties.newValue)
    | extend Target = tostring(TargetResources.userPrincipalName)
    | extend JoinAuditId = tolower(JoinId)
    | join kind=leftouter (
        TargetUserBA
        | where ActionType == "Add member to role"
        | extend JoinBAId = tolower(SourceRecordId)
        )
        on $left.JoinAuditId == $right.JoinBAId
    | extend
        AnomalyName = "Anomalous Role Assignment",
        Tactic = "Persistence", Technique = "Account Manipulation", SubTechnique = "",
        Description = "User performing Add member to role."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target, RoleName, ["Evidence"]=ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority;
let LogOns = materialize(
    TargetUserBA
    | where ActivityType == "LogOn"
);
let AnomalousResourceAccess = LogOns
    | where ActionType == "ResourceAccess"
    | where tostring(ActivityInsights.FirstTimeUserLoggedOnToDevice) =~ "True"
    | extend
        AnomalyName = "Anomalous Resource Access",
        Tactic = "Lateral Movement", Technique = "", SubTechnique = "",
        Description = "First time user logged on to device (ResourceAccess)."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["Evidence"]=ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority; 
let AnomalousRDPActivity = LogOns
    | where ActionType == "RemoteInteractiveLogon"
    | where tostring(ActivityInsights.FirstTimeUserLoggedOnToDevice) =~ "True"
    | extend
        AnomalyName = "Anomalous RDP Activity",
        Tactic = "Lateral Movement", Technique = "", SubTechnique = "",
        Description = "First time RDP Interactive Logon observed."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["Evidence"]=ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority; 
let AnomalousLogintoDevices = LogOns
    | where ActionType == "InteractiveLogon"
    | where tostring(ActivityInsights.FirstTimeUserLoggedOnToDevice) =~ "True"
    | where tostring(UsersInsights.DormantAccount) =~ "True" or tostring(DevicesInsights.LocalAdmin) =~ "True"
    | extend
        AnomalyName = "Anomalous Login To Devices",
        Tactic = "Privilege Escalation", Technique = "Valid Accounts", SubTechnique = "",
        Description = "Interactive login to device with dormant or admin indicators."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["Evidence"]=ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority; 
let AnomalousPasswordReset = TargetUserBA
    | where ActionType == "Reset user password"
    | extend JoinBAId = tolower(SourceRecordId)
    | join kind=leftouter (TargetAuditLogs) on $left.JoinBAId == $right.JoinId
    | mv-expand TargetResources
    | extend Target = tostring(TargetResources.userPrincipalName)
    | extend
        AnomalyName = "Anomalous Password Reset",
        Tactic = "Impact", Technique = "Account Access Removal", SubTechnique = "",
        Description = "User reset account password."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target, ["Evidence"]=ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority;
let AnomalousGeoLocationLogon = TargetUserBA
    | where ActionType == "Sign-in"
    | where tostring(ActivityInsights.FirstTimeUserConnectedFromCountry) =~ "True"
    | extend JoinBAId = tolower(SourceRecordId)
    | join kind=leftouter (TargetSigninLogs) on $left.JoinBAId == $right.JoinId
    | extend
        AnomalyName = "Anomalous Geo-Location Logon",
        Tactic = "Initial Access", Technique = "Valid Accounts", SubTechnique = "",
        Description = "Sign-in from a new geographic location."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["Evidence"]=ActivityInsights, ResourceDisplayName, AppDisplayName, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority; 
let AnomalousFailedLogon = TargetUserBA
    | where ActivityType == "LogOn"
    | extend JoinBAId = tolower(SourceRecordId)
    | join kind=leftouter (
        TargetSigninLogs  
        | where Status.errorCode == 50126
        )
        on $left.JoinBAId == $right.JoinId
    | extend
        AnomalyName = "Anomalous Failed Logon",
        Tactic = "Credential Access", Technique = "Brute Force", SubTechnique = "Password Guessing",
        Description = "User experienced a failed logon."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["Evidence"]=ActivityInsights, ResourceDisplayName, AppDisplayName, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority; 
let AnomalousAADAccountManipulation = TargetAuditLogs
    | where OperationName == "Update user"
    | mv-expand AdditionalDetails
    | where AdditionalDetails.key == "UserPrincipalName"
    | mv-expand TargetResources
    | extend Target = tostring(TargetResources.userPrincipalName)
    | extend JoinAuditId = tolower(JoinId)
    | join kind=leftouter ( 
        TargetUserBA
        | where ActionType == "Update user"
        | extend JoinBAId = tolower(SourceRecordId)
        )
        on $left.JoinAuditId == $right.JoinBAId
    | extend
        AnomalyName = "Anomalous Account Manipulation",
        Tactic = "Persistence", Technique = "Account Manipulation", SubTechnique = "",
        Description = "User account was updated or modified."
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target, ["Evidence"]=ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority;
let AnomalousAADAccountCreation = TargetUserBA
    | where ActionType == "Add user"
    | extend JoinBAId = tolower(SourceRecordId)
    | join kind=leftouter (TargetAuditLogs) on $left.JoinBAId == $right.JoinId
    | mv-expand TargetResources
    | extend Target = tostring(TargetResources.userPrincipalName)
    | extend
        AnomalyName = "Anomalous Account Creation",
        Tactic = "Persistence", Technique = "Create Account", SubTechnique = "Cloud Account",
        Description = "New user account created in tenant." 
    | project TimeGenerated, AnomalyName, Tactic, Technique, SubTechnique, Description, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target, ["Evidence"]=ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ["Anomaly Score"]=InvestigationPriority;
//FINAL OUTPUT (Chronological Timeline of Anomalies for Target User)
union kind=outer
    AnomalousSigninActivity,
    AnomalousRoleAssignment,
    AnomalousResourceAccess,
    AnomalousRDPActivity,
    AnomalousPasswordReset,
    AnomalousLogintoDevices,
    AnomalousGeoLocationLogon,
    AnomalousAADAccountManipulation,
    AnomalousAADAccountCreation,
    AnomalousFailedLogon
| sort by TimeGenerated desc 
```
