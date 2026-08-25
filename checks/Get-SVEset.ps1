function Get-SVEset($comp) {

    # process = C:\Program Files\ESET\ESET Security\ekrn.exe en C:\Program Files\ESET\RemoteAdministrator\Agent\ERAAgent.exe

    $ReturnValue = @()

    $ESET_key1 = "SOFTWARE\ESET\ESET Security\CurrentVersion\Info\"
    $ESET_key2 = "SOFTWARE\ESET\ESET Security\CurrentVersion\Info\"
    $ESET_Lic_Key = "SOFTWARE\ESET\ESET Security\CurrentVersion\LicenseInfo\"
    $ESET_Version_Key = "ProductVersion"
    $ESET_PatternVersion_Key = "ScannerVersion"
    $ESET_Lic_Expiration = "ExpirationDate"
    $ESET_Version = ""
    $ESET_PatternVersion = ""

    #If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $ESET_Version = $wmi.GetStringValue($hklm, $ESET_key1, $ESET_Version_Key)
        $ESET_Version = $ESET_Version.svalue

        If ([int]$ESET_Version.length -eq 0) {
            $ReturnValue += New-SVTestResult "Antivirus installed" "ESET File Security Unknown Version" $false
			#return $ReturnValue
			}
		ElseIf ([int]$ESET_Version.length -ne 0) {                          
            $ESET_PatternVersion = $wmi.GetStringValue($hklm, $ESET_key2, $ESET_PatternVersion_Key)
            $ESET_PatternVersion = $ESET_PatternVersion.svalue
		    $ReturnMsg = "ESET File Security - Version " + $ESET_Version

            $Diff2 = $ESET_PatternVersion.split("(")[1].split(")")[0]
            $Diff1="{0:D8}" -f (Get-Date -UFormat "%Y%m%d")
            $Diff0=$Diff1-$Diff2
            If ([int]$Diff0 -lt 7) {
                $AV_Ok = $true
                $ReturnMsg = $ReturnMsg + " - Pattern: " + $ESET_PatternVersion
                $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            else {
                $AV_Ok = $false
                $ReturnMsg = $ReturnMsg + " - Pattern: " + $ESET_PatternVersion
                $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            }
        #}
        Return New-SVTest "Antivirus" $ReturnValue
}
