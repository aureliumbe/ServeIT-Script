function Get-SVBackupExec4($BEjobs) {

   $BEjobs.Split("!") | foreach {
   $ReturnMsg = "BackupExec - Job:" + $_
   $ReturnValue += New-SVTestResult "Symantec BackupExec" $ReturnMsg $true   
   }

Return New-SVTest "Symantec BackupExec" $ReturnValue
}
