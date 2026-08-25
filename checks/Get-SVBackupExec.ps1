function Get-SVBackupExec($comp) {

  $hklm = 2147483650
  $BE_Version_key = "SOFTWARE\Symantec\Backup Exec For Windows\Backup Exec\Server\"
  $BE_SWUpdate_key = "SOFTWARE\Symantec\Backup Exec For Windows\Backup Exec\User Interface\"
  $Version = "ExeVersion"
  $Status = "Status"
  $SWUpdate = "Software Update Aailable"
  $BackupExec_Version = ""
  $BackupExec_Status = ""
  $BackupExec_SWUpdate = ""
  
  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'bengine%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += New-SVTestResult "Symantec BackupExec" "Not Installed" $true
      return New-SVTest "Symantec BackupExec" $ReturnValue

      }
  else
      {
      #      
      $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
      $BackupExec_Version = $wmi.GetStringValue($hklm, $BE_Version_key, $Version)
      $BackupExec_Version = $BackupExec_Version.svalue
      $BackupExec_Status = $wmi.GetStringValue($hklm, $BE_Version_key, $Status)
      $BackupExec_Status = $BackupExec_Status.svalue
      $BackupExec_SWUpdate = $wmi.GetStringValue($hklm, $BE_SWUpdate_key, $SWUpdate)
      $BackupExec_SWUpdate = $BackupExec_SWUpdate.svalue

      $ReturnMsg = "Version " + $BackupExec_Version + " installed"
      $ReturnValue += New-SVTestResult "Symantec BackupExec" $ReturnMsg $true

      ############################
      $BEjobs = Invoke-Command -ComputerName $comp -scriptblock (get-item Function:\Get-SVBackupExec2).scriptblock -ErrorAction Continue
          
      $BEjobs.Split("!") | foreach {
        $ReturnMsg = " + Job: " + $_
        if ($_ -like '*Succeeded*') {
            $ReturnValue += New-SVTestResult "Symantec BackupExec" $ReturnMsg $true   
            }
        elseif ($_ -eq "" -OR $_ -eq " " -OR $_ -eq "  ") {
                }
                else {
                     $ReturnValue += New-SVTestResult "Symantec BackupExec" $ReturnMsg $false
                     }
        }
      }
Return New-SVTest "Symantec BackupExec" $ReturnValue
}
