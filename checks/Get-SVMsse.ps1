function Get-SVMsse($comp) {

    $ReturnValue = @()

    #Microsoft Security Essentials AV Variables
    $MSSE_key1 = "SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates\"
    $MSSE_key2 = "SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates\"
    $MSSE_Version_Key = "AVSignatureVersion"
    # "AVSignatureApplied"=hex:00,9b,55,8c,89,61,d2,01
    $MSSE_PatternVersion_Key = "AVSignatureApplied"
    # BinaryToDate($MSSE_PatternVersion_Key)
    $MSSE_Version = ""
    $MSSE_PatternVersion = ""
  
    #Microsoft Windows Defender AV Variables (Windows 2016)
    $MSWD_key1 = "SOFTWARE\Microsoft\Windows Defender\Signature Updates\"
    $MSWD_key2 = "SOFTWARE\Microsoft\Windows Defender\Signature Updates\"
    $MSWD_Version_Key = "AVSignatureVersion"
    # "AVSignatureApplied"=hex:00,9b,55,8c,89,61,d2,01
    $MSWD_PatternVersion_Key = "AVSignatureApplied"
    # BinaryToDate($MSSE_PatternVersion_Key)
    $MSWD_Version = ""
    $MSWD_PatternVersion = ""
    $MSSE_AV_Ok = $false
    $MSWD_AV_Ok = $false

    If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $MSSE_Version = $wmi.GetStringValue($hklm, $MSSE_key1, $MSSE_Version_Key)
        $MSSE_Version = $MSSE_Version.svalue
	    If ($MSSE_Version.length -ne 0) {                          
            $MSSE_PatternVersion = $wmi.GetBinaryValue($hklm, $MSSE_key2, $MSSE_PatternVersion_Key)
            $MSSE_PatternVersion = $MSSE_PatternVersion.uvalue
            }
        elseif ([int]$MSSE_Version.length -eq 0) {
            $MSWD_Version = $wmi.GetStringValue($hklm, $MSWD_key1, $MSWD_Version_Key)
            $MSWD_Version = $MSWD_Version.svalue
            If ([int]$MSWD_Version.length -ne 0) {
                $MSWD_PatternVersion = $wmi.GetBinaryValue($hklm, $MSWD_key2, $MSWD_PatternVersion_Key)
                $MSWD_PatternVersion = $MSWD_PatternVersion.uvalue
	            }
            }
            else {
                $AV_Ok = $false        
                $ReturnMsg = "MS Security Essentials/MS Windows Defender Unknown Version"
                #$ReturnValue += New-SVTestResult "Antivirus installed" "MS Security Essentials/MS Windows Defender Unknown Version" $AV_Ok
				}
            }
	Else {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $MSSE_Version = $wmi.GetStringValue($hklm, $MSSE_key1, $MSSE_Version_Key)
        $MSSE_Version = $MSSE_Version.svalue
		If ($MSSE_Version -ne "") {                          
            $MSSE_PatternVersion = $wmi.GetBinaryValue($hklm, $MSSE_key2, $MSSE_PatternVersion_Key)
            $MSSE_PatternVersion = $MSSE_PatternVersion.uvalue
            }
        elseif ($MSSE_Version -eq "") {
            $MSWD_Version = $wmi.GetStringValue($hklm, $MSWD_key1, $MSWD_Version_Key)
            $MSWD_Version = $MSWD_Version.svalue
            If ($MSWD_Version -ne "") {
                $MSWD_PatternVersion = $wmi.GetBinaryValue($hklm, $MSWD_key2, $MSWD_PatternVersion_Key)
                $MSWD_PatternVersion = $MSWD_PatternVersion.uvalue
		        }
            }
            else {
                $AV_Ok = $false        
                $ReturnMsg = "MS Security Essentials/MS Windows Defender Unknown Version"
                #$ReturnValue += New-SVTestResult "Antivirus installed" "MS Security Essentials/MS Windows Defender Unknown Version" $AV_Ok
		        }
            }				  

            If ($MSSE_PatternVersion -eq "" -and $MSWD_PatternVersion -eq "" ) {
                $AV_Ok = $false        
                $ReturnMsg = "MS Security Essentials/MS Windows Defender Unknown Version"
                #$ReturnValue += New-SVTestResult "Antivirus installed" "MS Security Essentials/MS Windows Defender Unknown Version" $AV_Ok
			    }
			Else {
                if ($MSSE_PatternVersion -ne "") {
                    $ReturnMsg = "MS Security Essentials - Version " + $MSSE_Version

                    if ([int]$MSSE_PatternVersion.count -gt 3) {                        
                        $Seconds = $MSSE_PatternVersion[7]*[math]::pow( 2,56) + $MSSE_PatternVersion[6]*[math]::pow( 2,48) + $MSSE_PatternVersion[5]*[math]::pow( 2,40) + $MSSE_PatternVersion[4]*[math]::pow( 2,32) + $MSSE_PatternVersion[3]*[math]::pow( 2,24) + $MSSE_PatternVersion[2]*[math]::pow( 2,16) + $MSSE_PatternVersion[1]*[math]::pow( 2,8) + $MSSE_PatternVersion[0]
                        $LastModDay=[datetime]::FromFileTime($Seconds).ToString('yyyyMMdd')

                        }
                                           
                              $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

                              $PatternYear=$LastModDay.Substring(0,4)
                              $PatternMonth=$LastModDay.Substring(4,2)
                              $PatternDay=$LastModDay.Substring(6,2)

                              $PatternDate2=$PatternYear+"/"+$PatternMonth+"/"+$PatternDay

                              $PatternDate=(get-date "$PatternDate2").Ticks

                              if ($PatternDate -gt $TodayMinus7Days) {
                                  $AV_Ok = $true
                                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                                  $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                                  #$ReturnValue += New-SVTestResult "Antivirus Update" $LastModDay $true
                                  }
                              else {
                                  $AV_Ok = $false
                                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                                  $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok                        
                                  #$ReturnValue += New-SVTestResult "Antivirus Update" $LastModDay $false
                                  }
                    }
                    elseif ($MSWD_PatternVersion -ne "") {
                            $ReturnMsg = "MS Windows Defender - Version " + $MSWD_Version
                            #$ReturnValue += New-SVTestResult "Antivirus installed" $ReturnMsg $true
                            if ([int]$MSWD_PatternVersion.count -gt 3) {
                                $Seconds = $MSWD_PatternVersion[7]*[math]::pow( 2,56) + $MSWD_PatternVersion[6]*[math]::pow( 2,48) + $MSWD_PatternVersion[5]*[math]::pow( 2,40) + $MSWD_PatternVersion[4]*[math]::pow( 2,32) + $MSWD_PatternVersion[3]*[math]::pow( 2,24) + $MSWD_PatternVersion[2]*[math]::pow( 2,16) + $MSWD_PatternVersion[1]*[math]::pow( 2,8) + $MSWD_PatternVersion[0]
                                $LastModDay=[datetime]::FromFileTime($Seconds).ToString('yyyyMMdd')
                                }

                              $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

                              $PatternYear=$LastModDay.Substring(0,4)
                              $PatternMonth=$LastModDay.Substring(4,2)
                              $PatternDay=$LastModDay.Substring(6,2)

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
                }
        Return New-SVTest "Antivirus" $ReturnValue   
}
