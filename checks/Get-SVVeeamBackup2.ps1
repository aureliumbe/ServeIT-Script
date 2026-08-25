function Get-SVVeeamBackup2($comp) {
#
#https://richiban.uk/2012/08/23/ensuring-you-get-the-clr-version-you-want-when-remoting-in-powershell/
#
#After creating the files c:\windows\System32\wsmprovhost.exe.config and c:\windows\SysWOW64\wsmprovhost.exe.config with the following content, everything worked fine:
#<?xml version="1.0"?>
#<configuration>
#    <startup useLegacyV2RuntimeActivationPolicy="true">
#         <supportedRuntime version="v4.0.30319"/>        
#         <supportedRuntime version="v2.0.50727"/>        
#    </startup>
#</configuration>

  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  #$CPUarch =  (Get-WmiObject win32_processor -computername $comp | Where-Object{$_.deviceID -eq "CPU0"}).AddressWidth
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%Veeam.Backup.Service%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += New-SVTestResult "Veeam Backup" "Not Installed" $true
      return New-SVTest "Veeam Backup" $ReturnValue
      }
  else
      {
      $filename = $processes.Path
      $filename = $filename.replace("Veeam.Backup.Service.exe","Veeam.Backup.Core.dll")
      $filename = $filename.replace("C:\","")
      #$filename = "\Program Files\Veeam\Backup and Replication\Veeam.Backup.Core.dll"
      $obj = New-Object System.Collections.ArrayList 
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $Veeam_Version = ($file.VersionInfo).fileversion
          }
      #last_successful_backup_time
      $ReturnMsg = "Version " + $Veeam_Version + " installed"
      $ReturnValue += New-SVTestResult "Veeam Backup" $ReturnMsg $true
      
      try {
        if ($Veeam_Version.split(".")[0] -lt 11) {
            $retcode = Invoke-Command -ComputerName $comp -ScriptBlock {Add-PSSnapin VeeamPSSnapin} -ErrorAction Stop
            $vbrTapeJobs = Invoke-Command -ComputerName $comp -ScriptBlock {Add-PSSnapin VeeamPSSnapin; Get-VBRTapeJob} -ErrorAction Stop
            }
        else {            
            $retcode = Invoke-Command -ComputerName $comp -ScriptBlock {Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process; Import-Module Veeam.Backup.PowerShell} -ErrorAction Stop
            $vbrTapeJobs = Invoke-Command -ComputerName $comp -ScriptBlock {Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process; Import-Module Veeam.Backup.PowerShell; Get-VBRTapeJob} -ErrorAction Stop
            }

        if ($vbrTapeJobs) {
            $CustomNextRun ='{0:dd/MM/yyyy HH:mm:ss}' -f $vbrTapeJobs.NextRun
            ##$ReturnMsg = " + Job: " + $vbrTapeJobs.Name + " - Status: " + $vbrTapeJobs.LastResult + " - NextRun: " + $CustomNextRun + " - Result: " + $vbrTapeSessionResult + " - State: " + $vbrTapeSession.state
            $ReturnMsg = " + Job: " + $vbrTapeJobs.Name + " - Status: " + $vbrTapeJobs.LastResult + " - State: " + $vbrTapeJobs.LastState + " - NextRun: " + $CustomNextRun
            $ReturnValue += New-SVTestResult "Veeam Backup" $ReturnMsg $true
            }
                     
            $VeeamVMjobStatus = Invoke-Command -ComputerName $comp -scriptblock ${Function:Get-SVVeeamJobStatus} -ArgumentList $Veeam_Version -ErrorAction Continue

            ## $VeeamVMjobStatus = Invoke-Command -ComputerName $comp -scriptblock (get-item Function:\Get-SVVeeamJobStatus).ScriptBlock -ErrorAction Continue
            ## $VeeamVMjobStatus = Invoke-Command -ComputerName $comp -scriptblock ${Function:Get-SVVeeamJobStatus} -ArgumentList $Veeam_Version

        }
      catch {
        Write-host "*****************************************************************************************************"
        Write-host "The Veeam PSSnapin is installed/Registered, but can not be executed."
        Write-host "Propably a Powershell (Version) incompatibility"
        Write-host "Check the following link:"
        Write-host "https://richiban.uk/2012/08/23/ensuring-you-get-the-clr-version-you-want-when-remoting-in-powershell/"
        Write-host "*****************************************************************************************************"
        Write-host ""
        }        

      if ($VeeamVMjobStatus) {
        $VeeamVMjobStatus.Split("!") | foreach {
            $ReturnMsg = $_
            if ( ($_ -like '*Success*') -or ($_ -like '*Warning*') ) {
                $ReturnValue += New-SVTestResult "Veeam Backup" $ReturnMsg $true   
                }
            elseif ($_ -like '*Failed*') {
                $ReturnValue += New-SVTestResult "Veeam Backup" $ReturnMsg $false
                }
            elseif ($_ -like '*None*') {
                $ReturnValue += New-SVTestResult "Veeam Backup" $ReturnMsg $true
                }
            }
        }
      else {
        $ReturnMsg = " + No Veeam Backup Jobs, or the free ZIP version"
        $ReturnValue += New-SVTestResult "Veeam Backup" $ReturnMsg $true
        }
  }
Return New-SVTest "Veeam Backup" $ReturnValue
}
