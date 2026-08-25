function Get-SVMcAfee($comp){

    $ReturnValue = @()

    #McAfee McShield AV Variables
    $McAfee_64_key1 = "SOFTWARE\Wow6432Node\McAfee\DesktopProtection\"
    $McAfee_32_key1 = "SOFTWARE\McAfee\DesktopProtection\"
    $McAfee_64_key2 = "SOFTWARE\Wow6432Node\McAfee\AVEngine\"
    $McAfee_32_key2 = "SOFTWARE\McAfee\AVEngine\"
    $McAfee_Version_Key = "szProductVer"
    $McAfee_DatVersion_Key = "AVDatDate"
    $McAfee_Version = ""
    $McAfee_DatVersion = ""

    If ([int]$CPUarch -eq 64){
        # Check for McAfee McShield version on a a 64 bit machine szProductVer=8.8.0.1445, AVDatDate=2016/02/25
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $McAfee_Version = $wmi.GetStringValue($hklm, $McAfee_64_key1, $McAfee_Version_Key)
        $McAfee_Version = $McAfee_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $McAfee_DatVersion = $wmi.GetStringValue($hklm, $McAfee_64_key2, $McAfee_DatVersion_Key)
        $McAfee_DatVersion = $McAfee_DatVersion.svalue
        # Check for McAfee McShield version on a a 64 bit machine szProductVer=8.8.0.1445, AVDatDate=2016/02/25
        }
    else {
        # Check for McAfee McShield version on a a 32 bit machine szProductVer=8.8.0.1445, AVDatDate=2016/02/25
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $McAfee_Version = $wmi.GetStringValue($hklm, $McAfee_32_key1, $McAfee_Version_Key)
        $McAfee_Version = $McAfee_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $McAfee_DatVersion = $wmi.GetStringValue($hklm, $McAfee_32_key2, $McAfee_DatVersion_Key)
        $McAfee_DatVersion = $McAfee_DatVersion.svalue               
            
        }

    if ($McAfee_Version -eq ""){
        $ReturnValue += New-SVTestResult "Antivirus installed" "McAfee Unknown Version" $false
        #return $ReturnValue
        }
    else {         
              $ReturnMsg = "McAfee Version " + $McAfee_Version

              $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            
              #$McAfee_DatVersion="20170608"

              $PatternYear=$McAfee_DatVersion.Substring(0,4)
              $PatternMonth=$McAfee_DatVersion.Substring(5,2)
              if ([int]$PatternMonth -gt 12) {
                  $PatternMonth=$McAfee_DatVersion.Substring(8,2)
                  $PatternDay=$McAfee_DatVersion.Substring(5,2)
                  }
              else {
                  $PatternDay=$McAfee_DatVersion.Substring(8,2)
                  }
              $PatternDate2=$PatternYear+"/"+$PatternMonth+"/"+$PatternDay

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
