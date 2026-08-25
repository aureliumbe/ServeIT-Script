function Get-SVArcservBackup($comp) {

# COPRO
#$comp="CRMSERVER"

$file = ""
$filename = ""
$filepath = ""
$ReturnValue = @()
  
#$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%jobeng.exe%'" -ErrorAction Continue
#$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%DBEng.exe%'" -ErrorAction Continue
$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%DatastoreInstService.exe'" -ErrorAction Continue

if ($processes -eq $null) {
    $ReturnValue += New-SVTestResult "Arcserv Backup" "Not Installed" $true
    return New-SVTest "Arcserv Backup" $ReturnValue
    }
else {
    $filename = $processes.Path
    #$filename = $filename.replace("Veeam.Backup.Service.exe","Veeam.Backup.Core.dll")
    $filename = $filename.replace("C:\","")
    #$filename = "\Program Files\Veeam\Backup and Replication\Veeam.Backup.Core.dll"
    $obj = New-Object System.Collections.ArrayList 
    $filepath = Test-Path "\\$comp\c$\$filename"
    if ($filepath -eq "True") {
        $file = Get-Item "\\$comp\c$\$filename" 
        $Arcserv_Version = ($file.VersionInfo).fileversion
        }
      
    #last_successful_backup_time
    $ReturnMsg = "Version " + $ArcServ_Version + " installed"
    $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $true

    $All_ArcServeUPD_Jobs = Invoke-Command -ComputerName $comp -scriptblock {Invoke-Sqlcmd -Query "SELECT DISTINCT A.jobId, A.jobType, A.jobMethod, A.jobStatus, A.productType, A.jobUTCStartTime, A.jobUTCEndTime, A.serverId, A.agentId, B.nodeName FROM as_edge_d2dJobHistory_lastJob A INNER JOIN as_edge_session_details B ON A.agentId = B.nodeId ORDER BY A.jobUTCStartTime;" -ServerInstance "CRMSERVER\ARCSERVE_APP" -Database "arcserveUDP" } -ErrorAction SilentlyContinue

    foreach ($job in $All_ArcServeUPD_Jobs) {
        if ($job.jobStatus -eq "1") {
            if ($job.jobType -eq "0" -OR $job.jobType -eq "3") {
                #Write-Host Incremental Backup of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: Incremental Backup Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $true
                }
            elseif ($job.jobType -eq "11" -OR $job.jobType -eq "15") {
                #Write-Host File System Catalog of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: File System Catalog Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $true
                }
            elseif ($job.jobType -eq "32") {
                #Write-Host Merge on RPS of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: Merge Job on RPS:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $true
                }
            elseif ($job.jobType -eq "51") {
                #Write-Host Purge Job of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: Purge Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $true
                }
            }
        else {
            if ($job.jobType -eq "0" -OR $job.jobType -eq "3") {
                #Write-Host Incremental Backup of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: Incremental Backup Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $false
                }
            elseif ($job.jobType -eq "11" -OR $job.jobType -eq "15") {
                #Write-Host File System Catalog of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: File System Catalog Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $false
                }
            elseif ($job.jobType -eq "32") {
                #Write-Host Merge on RPS of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: Merge Job on RPS:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $false
                }
            elseif ($job.jobType -eq "51") {
                #Write-Host Purge Job of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: Purge Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += New-SVTestResult "Arcserv Backup" $ReturnMsg $false
                }
            }
        }

    }
Return New-SVTest "Arcserv Backup" $ReturnValue
}
