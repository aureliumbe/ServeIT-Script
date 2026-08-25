function Get-SVReplicationHealth($comp){

<#
$LogName="FRS Replication"
$Source="FRS"
$Eventid=13568
$Message="*The DFS Replication service stopped replication*"
#>

$LogName="DFS Replication"
$Source="DFSR"
$Eventid=2213
$Message="*The DFS Replication service stopped replication*"

$ReturnValue = @()
$ReturnMsg = ""

$StartTime = (Get-date).AddDays(-7)

if ($domain.DomainControllers.name -Contains ($comp+"."+$domain.name).ToUpper()) {
    # If error: Get-WinEvent : The RPC server is unavailable => Select Inbound Rules and in the list, right-click Remote Event Log Management (RPC) and select Enable Rule.
    #$Events = Get-EventLog -ComputerName $comp -LogName $LogName -Source $Source -After (Get-Date).AddDays(-60) | Where-Object {$_.EventID -eq $EventId} | sort TimeGenerated | select -last 1
    $Events = Get-WinEvent -FilterHashtable @{LogName=$LogName;ID=$EventId;StartTime=$StartTime} -MaxEvents 1 -ComputerName $comp -ErrorAction SilentlyContinue

    if ($Events -ne $null) {
        $ReturnMsg = "Eventid:"+$EventId+" Unhealthy"
        $ReturnValue += New-SVTestResult "DFSR SYSVOL Replication" $ReturnMsg $false
        }
    else {
        $ReturnMsg = "Eventid:"+$EventId+" Healthy"
        $ReturnValue += New-SVTestResult "DFSR SYSVOL Replication" $ReturnMsg $true
        }
    }
else {
    $ReturnValue += New-SVTestResult "DFSR SYSVOL Replication" "Not Installed" $true
    }

$LogName="DFS Replication"
$Source="DFSR"
$EventId=4012
$Message="*DFS*"

if ($domain.DomainControllers.name -Contains ($comp+"."+$domain.name).ToUpper()) {
    # If error: Get-WinEvent : The RPC server is unavailable => Select Inbound Rules and in the list, right-click Remote Event Log Management (RPC) and select Enable Rule.
    #$Events = Get-EventLog -ComputerName $comp -LogName $LogName -Source $Source -After (Get-Date).AddDays(-60) | Where-Object {$_.EventID -eq $EventId} | sort TimeGenerated | select -last 1
    $Events = Get-WinEvent -FilterHashtable @{LogName=$LogName;ID=$EventId;StartTime=$StartTime} -MaxEvents 1 -ComputerName $comp -ErrorAction SilentlyContinue

    if ($Events -ne $null) {
        $ReturnMsg = "Eventid:"+$EventId+" Unhealthy"
        $ReturnValue += New-SVTestResult "DFSR SYSVOL Replication" $ReturnMsg $false
        }
    else {
        $ReturnMsg = "Eventid:"+$EventId+" Healthy"
        $ReturnValue += New-SVTestResult "DFSR SYSVOL Replication" $ReturnMsg $true
        }
    }
else {
    $ReturnValue += New-SVTestResult "DFSR SYSVOL Replication" "Not Installed" $true
    }


return New-SVTest "DFSR SYSVOL Replication Health" $ReturnValue
}
