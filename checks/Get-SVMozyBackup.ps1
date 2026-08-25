function Get-SVMozyBackup($comp) {
#
# File version of MozyPro : 2.28.2.432 "C:\Program Files\MozyPro\oem.dll"
# MozyProBackup.exe
# MozyProStat.exe

# HKLM\Software\MozyPro\state\
# "last_successful_seed_time"="2013-05-17 23:27:54"
# "last_successful_backup_time"="2016-03-06 21:36:43"
# "last_successful_backup_files"="634919"
# "last_successful_backup_size"="575098801098"

  $hklm = 2147483650
  $key = "SOFTWARE\MozyPro\state\"
  $Last_BU_Time_Key = "last_successful_backup_time"
  $Last_BU_Files_Key = "last_successful_backup_files"
  $Last_BU_Size_Key = "last_successful_backup_size"
  $Last_BU_Time = ""
  $Last_BU_Date = ""
  $Last_BU_Files = ""
  $Last_BU_Size = ""

  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%MozyProBackup%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += New-SVTestResult "MozyPro Backup" "Not Installed" $true
      return New-SVTest "MozyPro Backup" $ReturnValue
      }
  else
      {
      $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
      $Last_BU_Time = $wmi.GetStringValue($hklm, $Key, $Last_BU_Time_Key)
      $Last_BU_Time = $Last_BU_Time.svalue
      $Last_BU_Files = $wmi.GetStringValue($hklm, $Key, $Last_BU_Files_Key)
      $Last_BU_Files = $Last_BU_Files.svalue
      $Last_BU_Size = $wmi.GetStringValue($hklm, $Key, $Last_BU_Size_Key)
      $Last_BU_Size = $Last_BU_Size.svalue

      $filename = "\Program Files\MozyPro\oem.dll" 
      $obj = New-Object System.Collections.ArrayList 
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $MozyPro_Version = ($file.VersionInfo).fileversion
          }      
      $ReturnMsg = "Version " + $MozyPro_Version + " installed"
      $ReturnValue += New-SVTestResult "MozyPro Backup" $ReturnMsg $true

      $Last_BU_Date = $Last_BU_Time.split(" ")[0]
      $Last_BU_Date = $Last_BU_Date.replace("-","/")
      $BackupDateTicks =(get-date "$Last_BU_Date").Ticks
      $Last_BU_Date ="{0:D8}" -f $Last_BU_Date.replace("/","")
      $TodayMinus5DaysTicks =((Get-Date).AddDays(-5)).Ticks
            
      $ReturnMsg1 = "Last Successful Backup Time " + $Last_BU_Date
      $ReturnMsg2 = "Last Successful Backup Files " + $Last_BU_Files
      $ReturnMsg3 = "Last Successful Backup Size " +  [math]::Round(($Last_BU_Size/1024/1024/1024),2) + " GBytes"
      
      If ($BackupDateTicks -gt $TodayMinus5DaysTicks) {
          $ReturnValue += New-SVTestResult "MozyPro Status" $ReturnMsg1 $true
          $ReturnValue += New-SVTestResult "MozyPro Status" $ReturnMsg2 $true
          $ReturnValue += New-SVTestResult "MozyPro Status" $ReturnMsg3 $true
          }
      else {
          $ReturnValue += New-SVTestResult "MozyPro Status" $ReturnMsg1 $false
          $ReturnValue += New-SVTestResult "MozyPro Status" $ReturnMsg2 $false
          $ReturnValue += New-SVTestResult "MozyPro Status" $ReturnMsg3 $false
          }
      }
Return New-SVTest "MozyPro Backup" $ReturnValue
}
