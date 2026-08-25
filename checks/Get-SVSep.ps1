function Get-SVSep($comp) {

    $ReturnValue = @()

    #Symantec SEP AV Variables
    $SEP_64_key1 = "SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\"
    $SEP_32_key1 = "SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\"
    $SEP_64_key2 = "SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\"
    $SEP_32_key2 = "SOFTWARE\Symantec\Symantec Endpoint Protection\AV\"
    $SEP_Version_Key = "PRODUCTVERSION"
    $SEP_PatternVersion_Key = "PatternFileDate"
    $SEP_Version = ""
    $SEP_PatternVersion = ""
    $SEP_AV_Ok = $false

    If ([int]$CPUarch -eq 64) {
        # Check for SEP version on a 64 bit machine PRODUCTERSION=12.1.5337.5000, PatternFileDate=46 01 26 00 00 00 00 00 / 46, 8, 8, 0
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $SEP_Version = $wmi.GetStringValue($hklm, $SEP_64_key1, $SEP_Version_Key)
        $SEP_Version = $SEP_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $SEP_PatternVersion = $wmi.GetBinaryValue($hklm, $SEP_64_key2, $SEP_PatternVersion_Key)
        $SEP_PatternVersion = $SEP_PatternVersion.uvalue
        }
    Else {
        # Check for SEP version on a 32 bit machine PRODUCTERSION=12.1.5337.5000, PatternFileDate=46 01 26 00 00 00 00 00
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $SEP_Version = $wmi.GetStringValue($hklm, $SEP_32_key1, $SEP_Version_Key)
        $SEP_Version = $SEP_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $SEP_PatternVersion = $wmi.GetBinaryValue($hklm, $SEP_32_key2, $SEP_PatternVersion_Key)
        $SEP_PatternVersion = $SEP_PatternVersion.uvalue
        }

    if ($SEP_Version -eq "") {
        $SEP_AV_Ok = $false        
        $ReturnMsg = "SEP Unknown Version"       
        }
    else {         
        $ReturnMsg = "SEP version " + $SEP_Version
        #$ReturnValue += New-SVTestResult "Antivirus installed" $ReturnMsg $true
        if ([int]$SEP_PatternVersion.count -gt 3) {
            $year = $SEP_PatternVersion[0]+1970
            $month = $SEP_PatternVersion[1]+1
            $day = $SEP_PatternVersion[2]
            }
                  $SEP_PatternYear = "{0:D4}" -f $year
                  $SEP_PatternMonth = "{0:D2}" -f $month
                  $SEP_PatternDay = "{0:D2}" -f $day


                  $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

                  $PatternDate2=$SEP_PatternYear+"/"+$SEP_PatternMonth+"/"+$SEP_PatternDay

                  $PatternDate=(get-date "$PatternDate2").Ticks
                  #$TodayDate=(get-date).Ticks

                  if ($PatternDate -gt $TodayMinus7Days) {
                      $AV_Ok = $true
                      $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                      $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                      }
                  else {
                      $AV_Ok = $false
                      $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                      $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                      }
        }        
    Return New-SVTest "Antivirus" $ReturnValue            
}
