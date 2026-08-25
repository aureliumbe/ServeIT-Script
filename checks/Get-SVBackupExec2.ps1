function Get-SVBackupExec2() {

Import-module "C:\Program Files\Symantec\Backup Exec\Modules\BEMCLI"

$BEJobs = get-BEJob | Select Name | sort-object Name
foreach ($BEJob in $BEJobs) {
    $LastJob = Get-BEJob $BEJob.Name | Get-BEJobHistory | Select -Last 1
    $CustomEndTime ='{0:dd/MM/yyyy hh:mm:ss}' -f $Lastjob.Endtime
    $ReturnMsg = $ReturnMsg + $LastJob.Name + " " + $LastJob.JobStatus + " " + $CustomEndTime + "!"
    }        
      
Return $ReturnMsg
}
