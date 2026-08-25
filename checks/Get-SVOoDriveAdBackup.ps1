function Get-SVOoDriveAdBackup($comp) {

  $processes = $null
  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%VVSvrDae%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += New-SVTestResult "OODrive AdBE Backup" "Not Installed" $true
      return New-SVTest "OODrive AdBE Backup" $ReturnValue
      }
  else
      {
      $filename = "Program Files (x86)\AdBE\CentralControl\VVAdmin.exe"

      $obj = New-Object System.Collections.ArrayList 
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $AdBE_Backup_Version = ($file.VersionInfo).fileversion
          $BuildDate = (($file.LastWriteTime).Day).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Month).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Year).ToString()
          $BuildDate = $BuildDate + " " + (($file.LastWriteTime).Hour).ToString()
          $BuildDate = $BuildDate + ":" + (($file.LastWriteTime).Minute).ToString()
          }
      #last_successful_backup_time
      $ReturnMsg = "Version " + $AdBE_Backup_Version + " Build: " + $BuildDate + " installed"
      $ReturnValue += New-SVTestResult "OODrive AdBE Backup" $ReturnMsg $true
      }
Return New-SVTest "OODrive AdBE Backup" $ReturnValue
}
