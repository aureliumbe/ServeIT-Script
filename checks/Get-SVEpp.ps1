function Get-SVEpp($comp) {

    # process = C:\Program Files (x86)\CheckPoint\Endpoint Security\Endpoint Common\bin\cpda.exe

    $ReturnValue = @()

    $CP_EPP_key1 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\"
    $CP_EPP_key2 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\Anti-Malware"
    $CP_EPP_key3 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\AntiBot"
    $CP_EPP_key4 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\Device Agent"
    $CP_EPP_key5 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\Threat Emulation"
    $CP_EPP_key1_Version_Key = "Version"
    $CP_EPP_key1_LastInstall ="LastInstallFinishTime"
    $CP_EPP_key2_Version_Key = "AVEngineVersion"
    $CP_EPP_key2_Lic_Exp_Key = "AVEngineLicense"
    $CP_EPP_key3_Version_Key = "Version"
    $CP_EPP_key4_Version_Key = "Version"
    $CP_EPP_key4_Pattern_Key = "PATVersion"
    $CP_EPP_key5_Version_Key = "Version"
    $CP_EPP_Version = ""
    $CP_EPP_PatternVersion = ""

    #If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $CP_EPP_Version = $wmi.GetStringValue($hklm, $CP_EPP_key1, $CP_EPP_key1_Version_Key)
        $CP_EPP_Version = $CP_EPP_Version.svalue

        If ([int]$CP_EPP_Version.length -eq 0) {
            $ReturnValue += New-SVTestResult "Antivirus installed" "Checkpoint Endpoint Security Unknown Version" $false
			#return $ReturnValue
			}
		ElseIf ([int]$CP_EPP_Version.length -ne 0) {
            $CP_EPP_PatternVersion = $wmi.GetDWORDValue($hklm, $CP_EPP_key1, $CP_EPP_key1_LastInstall)
            $CP_EPP_PatternVersion = $CP_EPP_PatternVersion.uvalue
		    $ReturnMsg = "Checkpoint Endpoint Security - Version: " + $CP_EPP_Version

            $ReturnMsg = $ReturnMsg + " - Date:" + $CP_EPP_PatternVersion
            $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $true
            }
        #}
        Return New-SVTest "Antivirus" $ReturnValue
}
