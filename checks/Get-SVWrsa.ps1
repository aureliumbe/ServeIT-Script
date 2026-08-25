function Get-SVWrsa($comp) {

    #Webroot SecureAnywhere AV Variables
    # initialOSBuildNumber = hexwaarde= 0x00001db1 = 7601
    #Webroot_64_Key = "SOFTWARE\Wow6432Node\webroot\"
    #Webroot_Version_Key = "initialOSBuildNumber"
    #Service is WRSA / WRSVC
    # "C:\Program Files (x86)\Webroot\WRSA.exe"
    #File Version 9.0.8.72
    #Product Version 9.0.8.72
    #Date Modified 4/03/2016 10:25
    #SOFTWARE\Wow6432Node\WRData\Status\UpdateTime=DWORD=1489597941
    #SOFTWARE\Wow6432Node\WRData\Status\Version=SZString=9.0.15.50    
    
    $ReturnValue = @()

    $WRSA_key1 = "SOFTWARE\Wow6432Node\WRData\Status\"
    $WRSA_key2 = "SOFTWARE\Wow6432Node\WRData\Status\"
    $WRSA_Version_Key = "Version"
    $WRSA_PatternVersion_Key = "UpdateTime"
    $WRSA_Version = ""
    $WRSA_PatternVersion = ""

    If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $WRSA_Version = $wmi.GetStringValue($hklm, $WRSA_key1, $WRSA_Version_Key)
        $WRSA_Version = $WRSA_Version.svalue
		If ([int]$WRSA_Version.length -ne 0) {                          
            $WRSA_PatternVersion = $wmi.GetDWORDValue($hklm, $WRSA_key2, $WRSA_PatternVersion_Key)
            $WRSA_PatternVersion = $WRSA_PatternVersion.uvalue
		    $ReturnMsg = "Webroot SecureAnywhere Endpoint Protection - Version " + $WRSA_Version + " installed"
			#$ReturnValue += New-SVTestResult "Antivirus installed" $ReturnMsg $true
            }
        elseif ([int]$WRSA_Version.length -eq 0) {
            $ReturnValue += New-SVTestResult "Antivirus installed" "Webroot SecureAnywhere Endpoint Protection Unknown Version" $false
			#return $ReturnValue
			}
        }

        #$WRSA_PatternVersion="1489500000"
        $Diff1="{0:D8}" -f (Get-Date -UFormat "%Y%m%d")
        $Diff2=get-date "1/1/1970"
        $Diff2=$Diff2.AddSeconds($WRSA_PatternVersion)
        $Diff2="{0:D8}" -f (Get-Date $Diff2 -UFormat "%Y%m%d")
        $Diff0=$Diff1-$Diff2
        #$Diff0=$Diff1-20160101
        If ([int]$Diff0 -lt 7) {
            $AV_Ok = $true
            $ReturnMsg = $ReturnMsg + " - Pattern: " + $Diff2
            $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
            }
        else {
            $AV_Ok = $false
            $ReturnMsg = $ReturnMsg + " - Pattern: " + $Diff2
            $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
            }
        Return New-SVTest "Antivirus" $ReturnValue
}
