function Get-SVAcronisBackup($comp) {

  $hklm = 2147483650
  $key = "SOFTWARE\Wow6432Node\Acronis\CLI\"
  $AcroCMD_Key = "path"

  $AcroCMD_Val = ""
  $file = ""
  $filename = ""
  $Acronis_Backup_Version = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'arsm.exe%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += New-SVTestResult "Acronis Backup" "Not Installed" $true
      return New-SVTest "Acronis Backup" $ReturnValue
      }
  else
      {
      $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
      $AcroCMD_Val = $wmi.GetStringValue($hklm, $Key, $AcroCMD_Key)
      $AcroCMD_Val = $AcroCMD_Val.svalue

      #$filename = "Program Files (x86)\Acronis\CommandLineTool\acrocmd.exe"
      $filename = $AcroCMD_Val.replace("C:\","")
      $filename2 = $AcroCMD_Val

      $obj = New-Object System.Collections.ArrayList
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $Acronis_Backup_Version = ($file.VersionInfo).fileversion.replace(",",".")
          $BuildDate = (($file.LastWriteTime).Day).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Month).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Year).ToString()
          $BuildDate = $BuildDate + " " + (($file.LastWriteTime).Hour).ToString()
          $BuildDate = $BuildDate + ":" + (($file.LastWriteTime).Minute).ToString()
          }
      $ReturnMsg = "Version " + $Acronis_Backup_Version + " - " + $BuildDate + " installed"
      $ReturnValue += New-SVTestResult "Acronis Backup" $ReturnMsg $true
      }

      #$scriptblock = {"cmd /c " + $filename2 + " list plans"}
      $scriptblock = {cmd /c "C:\Program Files (x86)\Acronis\CommandLineTool\acrocmd.exe" list plans}
      $ReturnMsg = Invoke-Command -scriptblock $scriptblock -ComputerName $comp

      foreach ($line in $ReturnMsg) { 
        if ($line -like "*GUID*") {
            continue
            }
        if ($line -like "--------------------*") {
            continue
            }
        if ($line -like "The operation completed*") {
            continue
            }
        if ($line -ne "") {
            $line = $line.split(" ")
            $count=0
            $ln2=""
            foreach ($ln in $line) {
                if ($ln -ne "") {
                    if ([int]$count -lt 5) {
                        $ln2 = $ln2 + " " + $ln
                        $count++
                        }
                    }                
                }
            $ReturnMsg = "+ Job: " + $ln2
            if ($ln2 -like "*error*" -or $ln2 -like "*Failed*" ) {
                $ReturnValue += New-SVTestResult "Acronis Backup" $ReturnMsg $false
                }
            else {
                $ReturnValue += New-SVTestResult "Acronis Backup" $ReturnMsg $true
                }
            continue
            }
        write-host $line
        }

Return New-SVTest "Acronis Backup" $ReturnValue
}
