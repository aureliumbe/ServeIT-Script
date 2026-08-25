Function Get-SVScheduledTasks($comp){

    	$ReturnValue = @()
	
	    $ST = new-object -com Schedule.Service
        $ST.connect($comp)
        $Rootfolder = $ST.GetFolder("\")
        $ScheduledTasks = $Rootfolder.GetTasks(0)
	    $counter = 0
        foreach ($task in $ScheduledTasks | Select Name, State, Enabled, LastRunTime, LastTaskResult, NextRunTime, @{Name="RunAs";Expression={[xml]$xml = $_.xml ; $xml.Task.Principals.principal.userID}}){
       	    $taskname =$task.Name
            if ($taskname -ne "CreateExplorerShellUnelevatedTask") {
                if ([int]$taskname.Length -gt 30) {
                    $taskname = $taskname.Substring(0,30)
                    }
	            $taskresult=$task.LastTaskResult
                $taskEnabled = $task.Enabled
	            if ((-not( ([int]$taskresult -eq 0) -or ([int]$taskresult -eq 1) )) -and $taskenabled -and ($taskname -notlike "Optimize Start Menu*" -OR $taskname -notlike $CreateExplorerShellUnelevatedTask) ){
                    $counter = $counter +1
                    $ReturnValue += New-SVTestResult $taskname  $taskresult $false
                    }
                }
            }

	    if ([int]$counter -eq 0){
		    $ReturnValue += New-SVTestResult "All Tasks" "0" $true
	        }

    return New-SVTest "Scheduled Tasks" $ReturnValue
}
