function Get-SVSophos($comp) {

# process = C:\Program Files\Sophos\Sophos File Scanner\SophosFileScanner.exe

# Sophos AV
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\Version: 2.20.4.1 REG_SZ
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\InstallState: 0 REG_DW
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\LastGoodInstallTime: 1640098001691 REG_QW (Last Update: 21-12-2021 15h46)
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\E17FE03B-0501-4aaa-BC69-0129D965F311\LongName: Sophos Anti-Virus for Windows REG_SZ
#
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\E17FE03B-0501-4aaa-BC69-0129D965F311\InstalledVersion: 10.8.11.41 REG_SZ
# Regkey: HKLM\SOFTWARE\Sophos\Sophos File Scanner\Application\ProductVersion: 1.9.7.2 REG_SZ (C:\Program Files\Sophos\Sophos File Scanner\SophosFileScanner.exe of (SophosFS.exe)
# Regkey: HKLM\SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\EngineVersion: 3.83.3 REG_SZ
# Regkey: HKLM\SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\VirusDataVersion: 2021122003 REG_SZ
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\ProductVersion: 6.11.299 REG_SZ

    $ReturnValue = @()

    $CP_EPP_key1 = "SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\E17FE03B-0501-4aaa-BC69-0129D965F311\"
    $CP_EPP_key2 = "SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\"
    $CP_EPP_key3 = "SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\"
    $CP_EPP_key4 = "SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\"
    $CP_EPP_key1_Version_Key = "InstalledVersion"
    $CP_EPP_key3_LastInstall ="LastGoodInstallTime"
    $CP_EPP_key2_Version_Key = "EngineVersion"
    $CP_EPP_key4_Pattern_Key = "VirusDataVersion"
    $CP_EPP_Version = ""
    $CP_EPP_PatternVersion = ""

    #If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $CP_EPP_Version = $wmi.GetStringValue($hklm, $CP_EPP_key1, $CP_EPP_key1_Version_Key)
        $CP_EPP_Version = $CP_EPP_Version.svalue

        If ([int]$CP_EPP_Version.length -eq 0) {
            $ReturnValue += New-SVTestResult "Antivirus installed" "Sophos Antivirus Unknown Version" $false
			#return $ReturnValue
			}
		ElseIf ([int]$CP_EPP_Version.length -ne 0) {
            $CP_EPP_PatternVersion = $wmi.GetStringValue($hklm, $CP_EPP_key4, $CP_EPP_key4_Pattern_Key)
            $CP_EPP_PatternVersion = $CP_EPP_PatternVersion.svalue
		    $ReturnMsg = "Sophos Antivirus - Version: " + $CP_EPP_Version
            $CP_EPP_EngineVersion = $wmi.GetStringValue($hklm, $CP_EPP_key2, $CP_EPP_key2_Version_Key)
            $CP_EPP_EngineVersion = $CP_EPP_EngineVersion.svalue
		    $ReturnMsg = "Sophos Antivirus - InstallVersion: " + $CP_EPP_Version + " - EngineVersion: " + $CP_EPP_EngineVersion

            $ReturnMsg = $ReturnMsg + " - Date:" + $CP_EPP_PatternVersion
            $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $true
            }
        #}
        Return New-SVTest "Antivirus" $ReturnValue
}
