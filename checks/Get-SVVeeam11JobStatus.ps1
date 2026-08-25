function Get-SVVeeam11JobStatus() {

# Find all Backup, BackupSync and Replica jobs
$VbrJobs = Get-VBRJob | Where-Object {$_.JobType -eq "Backup" -or $_.JobType -eq "BackupSync" -or $_.JobType -eq "Replica"} | Sort-Object typetostring, JobType, name

Foreach($Job in $VbrJobs) {
    #Get Job Name
    $Jobname = $Job.Name
    $session=Get-VBRBackupSession | Where {$_.jobId -eq $job.Id.Guid} | Sort EndTimeUTC -Descending | Select -First 1
    if ($session -ne $null) {
        #Get VMs in Job
        #$Objects = $Job.GetObjectsInJob()
        $jobsessiontasks=$session.gettasksessions() | Sort Name
               
        #Get Last Backup
        $Backup = Get-VBRBackup | Where{$_.JobName -eq "$JobName" -and $_.jobId -eq $job.Id.Guid}
        #$LastBackup = $Backup.LastPointCreationTime
        $LastBackup = $Backup.MetaUpdateTime
        $CustomLastBackup ='{0:dd/MM/yyyy HH:mm:ss}' -f $LastBackup        

        #Get Last Backup Result
        $Result = $Job.GetLastResult()
                
        #write-host $Jobname " - " $LastBackup " - " $Result
        $ReturnMsg = $ReturnMsg + " + Job: " + $Jobname + " - " + $CustomLastBackup + " - " + $Result + "!"

        foreach ($VM in $jobsessiontasks) {
            #write-host "   -> " $VM.name $VM.status
            $ReturnMsg = $ReturnMsg + "   -> VM: " + $VM.name + " - " + $VM.status + "!"
            }
        }
    }
Return $ReturnMsg
}
