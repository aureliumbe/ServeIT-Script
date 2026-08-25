function Get-SVVeeamVMstatusFailed($OrigJobName) {

if ($Veeam_Version.split(".")[0] -lt 11) {
    Add-PSSnapin VeeamPSSnapin
    }
else {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    Import-Module Veeam.Backup.PowerShell
    }

# Find all backup job sessions that have ended in the last x hours
$vbrjobs = Get-VBRJob | Where-Object {$_.JobType -eq "Backup" -or $_.JobType -eq "Replica"}
$vbrsessions = Get-VBRBackupSession | Where-Object {($_.JobType -eq "Backup" -or $_.JobType -eq "BackupSync" -or $_.JobType -eq "Replica") -and $_.EndTime -ge (Get-Date).addhours(-24)} | sort-object Name

# Find all successfully backed up VMs in selected sessions (i.e. VMs not ending in failure) and update status to "Protected"
if ($vbrsessions) {
    foreach ($session in $vbrsessions) {
        foreach ($vm in ($session.gettasksessions() | Where-Object {$_.Status -eq "Failed" -and $_.JobName -eq $OrigJobName} | ForEach-Object { $_ } | sort-object Name)) {
            #Write-Host $vm.Name $vm.JobName $vm.Status
            $ReturnMsg = $ReturnMsg + $vm.Name + " " + $vm.JobName + " " + $vm.Status + "!"
            }
        }
    }
Return $ReturnMsg
}
