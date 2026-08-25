function Get-SVCarboniteBackup($comp) {

  $hklm = 2147483650
  $BE_Version_key = "SOFTWARE\Zmanda\ZWC\1.0\Install\"
  
  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'ZWCService.exe%'" -ErrorAction Continue
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'ZCBService.exe%'" -ErrorAction Continue

  if ($processes -eq $null)
      {
      $ReturnValue += New-SVTestResult "Carbonite Backup" "Not Installed" $true
      return New-SVTest "Carbonite Backup" $ReturnValue

      }
  else
      {
      $filename = $processes.Path
      #$filename = $filename.replace("C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\bin\ZWCService.exe")
      #$filename = "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql.exe"
      $filename = $filename.replace("\bin\ZCBService.exe","\Database\bin\mysql.exe")
     
      #$CarboniteJobs = & "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql" -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio, EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus, BackupDetails FROM ZIBCatalog.ZIBreport WHERE Operation like '%ZIB_BACKUP_DIRECT_UPLOAD%' AND BackupStartTime >= DATE(NOW()) + INTERVAL - 1 DAY"
      #$CarboniteJobs = & "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql" -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio, EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus FROM ZIBCatalog.ZIBreport WHERE Operation like '%ZIB_BACKUP_DIRECT_UPLOAD%' AND BackupStartTime >= DATE(NOW()) + INTERVAL - 1 DAY \G"
      #$CarboniteJobs = & "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql" -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT * FROM information_schema.tables \G"
      
#      $CarboniteJobs = Invoke-Command -ComputerName $comp -scriptblock {
#        PARAM($Param1)
#        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio, 
#                                                                 EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus 
#                                                                 FROM ZIBCatalog.ZIBreport 
#                                                                 WHERE Operation like '%ZIB_BACKUP%' ORDER BY BackupType DESC LIMIT 2 \G"} -ArgumentList $FileName

      $CarboniteJob1 = Invoke-Command -ComputerName $comp -scriptblock {
        PARAM($Param1)
        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "
        SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio,
               EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus
        FROM ZIBCatalog.ZIBreport
        WHERE BackupStatus like '%ZIB_BACKUP%' AND BackupType = 'Windows File System'
        ORDER BY BackupStartTime DESC LIMIT 1
        \G"} -ArgumentList $FileName

      <#
      $CarboniteJob2 = Invoke-Command -ComputerName $comp -scriptblock {
        PARAM($Param1)
        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "
        SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio,
               EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus
        FROM ZIBCatalog.ZIBreport
        WHERE BackupStatus like '%ZIB_BACKUP%' AND BackupType = 'Windows System State'
        ORDER BY BackupStartTime DESC LIMIT 1
        \G"} -ArgumentList $FileName
      #>

      $CarboniteJob3 = Invoke-Command -ComputerName $comp -scriptblock {
        PARAM($Param1)
        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "
        SELECT BackupId, BackupSet, Operation, OperationStartTime, OperationEndTime, Status
        FROM ZIBCatalog.ZIBmonitor
        #WHERE Status = 'ZIB_BACKUP_SUCCESSFUL' OR Status = 'ZIB_UPLOAD_SUCCESSFUL'
        WHERE Status = 'ZIB_BACKUP_DIRECT_UPLOAD_SUCCESSFUL' OR Status = 'ZIB_BACKUP_DIRECT_BACKUP_SUCCESSFUL' OR Status = 'ZIB_BACKUP_SUCCESSFUL' OR Status = 'ZIB_UPLOAD_SUCCESSFUL'
        \G"} -ArgumentList $FileName

        #WHERE BackupStatus like '%ZIB_BACKUP%' of ZIB_BACKUP_SUCCESSFUL of ZIB_BACKUP_WARNING of ZIB_BACKUP_FAILED
        #ORDER BY BackupStartTime

      #GROUP BY BackupType
      #FROM ZIBCatalog.ZIBreport 
      #WHERE Operation like '%ZIB_BACKUP%'
      #GROUP BY BackupType ORDER BY BackupStartTime ASC LIMIT 2 \G"} -ArgumentList $FileName
      #WHERE Operation like '%ZIB_BACKUP_DIRECT_UPLOAD%' AND BackupStartTime >= DATE(NOW()) + INTERVAL - 1 DAY \G"} -ArgumentList $FileName
      #WHERE Operation like '%ZIB_BACKUP%' ORDER BY BackupStartTime DESC LIMIT 4 \G"} -ArgumentList $FileName

      ############################################################################
      #for ($i=0; $i -le $CarboniteJob3.length; $i++) {$CarboniteJob3[$i]}
      ############################################################################

      $ReturnMsg = ""
      $NoJobError=$false
      $LinesPerJobOutput = 0

      if ($CarboniteJob1 -eq $null) {
        $ReturnMsg = "No Jobs Found"
        $ReturnValue += New-SVTestResult "Carbonite Backup" $ReturnMsg $false
        }
      else {
            $i=0
            $ReturnMsg = "Version " + $CarboniteJob1[($i*$CarboniteJob1.Count)+2] + " installed"
            $ReturnValue += New-SVTestResult "Carbonite Backup" $ReturnMsg $true            

            $CarboniteCopyMonitorLines = $CarboniteJob3.length

            for ($i=0; $i -le $CarboniteCopyMonitorLines; $i++) {
                   if ($i%7 -eq 2) {
                        $CarboniteJobName = $CarboniteJob3[$i]
                        }
                   if ($i%7 -eq 4) {
                        $CarboniteJobStartTime = $CarboniteJob3[$i]
                        }
                   if ($i%7 -eq 5) {
                        $CarboniteJobEndTime = $CarboniteJob3[$i]
                        }
                   if ($i%7 -eq 6) {
                        $CarboniteJobStatus = $CarboniteJob3[$i]
                        }

                   if ($CarboniteJobStatus -like '*_SUCCESSFUL*') {
                        $NoJobError=$true
                        }
            
                   if ($i -ne 0 -AND ($i % 7) -eq 0) {
                        if ($CarboniteJobStatus -like '*_UPLOAD_SUCCESSFUL*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Cloud Backup Successful"
                            }
                        elseif ($CarboniteJobStatus -like '*_BACKUP_SUCCESSFUL*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Local Backup Successful"
                            }
                        elseif ($CarboniteJobStatus -like '*_UPLOAD_FAILED*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Cloud Backup Failed"
                            }
                        elseif ($CarboniteJobStatus -like '*_BACKUP_FAILED*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Local Backup Failed"
                            }
                        elseif ($CarboniteJobStatus -like '*_UPLOAD_WARNING*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Cloud Backup Warning"
                            }
                        elseif ($CarboniteJobStatus -like '*_BACKUP_WARNING*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Local Backup Warning"
                            }
                        else {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Backup problems"
                            }
                   
                        $Current=(Get-Date)
                        $diff= New-TimeSpan -Start $CarboniteJobStartTime -End $Current

                        if ( ($diff.days -gt 1 -AND $CarboniteJobName -notlike '*System State*') -OR !$NoJobError) {                                  
                           $ReturnValue += New-SVTestResult "Carbonite Backup" $ReturnMsg $false
                            }
                        Elseif ( ($diff.days -gt 31 -AND $CarboniteJobName -like '*System State*') -OR !$NoJobError ) {
                            $ReturnValue += New-SVTestResult "Carbonite Backup" $ReturnMsg $NoJobError
                            }
                        Else {
                           $ReturnValue += New-SVTestResult "Carbonite Backup" $ReturnMsg $NoJobError
                            }
                        }

                   }

            }
    }
Return New-SVTest "Carbonite Backup" $ReturnValue
}
