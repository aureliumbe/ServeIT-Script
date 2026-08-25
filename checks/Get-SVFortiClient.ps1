function Get-SVFortiClient($comp) {

<#    
    PMV: Antivirus Check for FortiClient, check of FortiClient actief is als AV:
    (Get-ItemProperty HKLM:\SOFTWARE\Fortinet\FortiClient\FA_AV -Name Enabled).enabled -eq 1
    
    Forticlient Versie:
    Get-WmiObject -Class Win32_Product | where {$_.name -like "*FortiClient*"} | select Version
    SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{17748981-CA57-4D18-8B08-5685F656221D}

    en potentieel last update time (maar deze ben ik niet 100% zeker dat die datum/tijd klopt)
    [System.DateTimeOffset]::FromUnixTimeSeconds((Get-ItemProperty HKLM:\SOFTWARE\Fortinet\FortiClient\FA_UPDATE -Name lastupdatetime).lastupdatetime).dateTime.toString("dd/MM/yyyy hh:mm:ss")
    er moet mss wel gechecked worden of de registry directory "sFortinet\FortiClient\FA_AV" bestaat, want op mijn pc staat die bvb niet (ik heb enkel forticlient voor vpn)
#>
    $ReturnValue = @()
    $hklm = 2147483650

    $Forticlient_Enabled_key = "SOFTWARE\Fortinet\FortiClient\FA_AV\"
    $Forticlient_LastUpdateTime_key = "SOFTWARE\Fortinet\FortiClient\FA_UPDATE\"
    
    $Forticlient_Enabled_Item = "Enabled"
    $Forticlient_LastUpdateTime_Item = "lastupdatetime"

    $Forticlient_Enabled = ""
    $Forticlient_LastUpdateTime_Value = ""

    $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -ErrorAction Continue
    foreach ($proc in $processes) {
        if ($proc.name -eq "fmon.exe") {
            $Filename = $Proc.ExecutablePath
            }
        }

    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename

    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    $Forticlient_Enabled = $wmi.GetDWORDValue($hklm, $Forticlient_Enabled_key, $Forticlient_Enabled_Item)
    $Forticlient_Enabled = $Forticlient_Enabled.uvalue

    $Forticlient_LastUpdateTime_Value = $wmi.GetDWORDValue($hklm, $Forticlient_LastUpdateTime_key, $Forticlient_LastUpdateTime_Item)
    $Forticlient_LastUpdateTime_Value = $Forticlient_LastUpdateTime_Value.uvalue
    $Forticlient_LastUpdateTime_Value = [System.DateTimeOffset]::FromUnixTimeSeconds($Forticlient_LastUpdateTime_Value).dateTime.toString("dd/MM/yyyy")
        
    If ([int]$Filename.length -eq 0) {
        $ReturnValue += New-SVTestResult "Antivirus installed" "FortiClient Unknown Version" $false
		}
    Else {
	    $ReturnMsg = "FortiClient - Version: " + $FileVersion
        $ReturnMsg = $ReturnMsg + " - Date:" + $Forticlient_LastUpdateTime_Value
        $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $true
        }

    Return New-SVTest "Antivirus" $ReturnValue
}
