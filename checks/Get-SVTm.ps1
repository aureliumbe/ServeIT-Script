function Get-SVTm($comp){

	$ReturnValue = @()

	#Trendmicro WFBS Variables
	$OfcService_64_Key = "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.\"
	$OfcService_32_Key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.\"
    $OfcServices_Key = "SYSTEM\CurrentControlSet\Services\TmPreFilter\Parameters\"
	#$OfcService_Version_Key = "ofcservice_ver"
	$Client_Version_Key ="TmListen_Ver"
	$Server_Version_Key = "ofcservice_ver"
	$TmFilter_Version_Key = "TmFilter-Ver"
	$Tm_PatternDate_Key = "PatternDate"
    $UpdateFrom_Key = "UpdateFrom"
    #RCS = DWORD = 101 => 202 (RDS)
    $RCS_Key = "RCS"    
    #EnableMiniFilter = DWORD = 0 => 1 (RDS)
    $EnableMiniFilter_Key = "EnableMiniFilter"
	$Server_Version = ""
	$Client_Version = ""
	$TmFilter_Version = ""
	$Tm_PatternDate = ""
    $UpdateFrom = ""
    $RCS_Val = ""
    $MiniFIlter_Val = ""
    $TM_WFBS_Services = $false
    $Tm_AV_Ok = $false

    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

	If ([int]$CPUarch -eq 64) {
		# Check for Trendmicro WFBS version on a 64 bit machine TmListen_Ver=19.0.3273          
		$Client_Version = $wmi.GetStringValue($hklm, $OfcService_64_Key, $Client_Version_Key)
		$Client_Version = $Client_Version.svalue
		$Server_Version = $wmi.GetStringValue($hklm, $OfcService_64_Key, $Server_Version_Key)
		$Server_Version = $Server_Version.svalue
		$UpdateFrom = $wmi.GetStringValue($hklm, $OfcService_64_Key, $UpdateFrom_Key)
		$UpdateFrom = $UpdateFrom.svalue
        # RCS_Val = 202 for (RDS/Citrix Server)
        $RCS_Val = $wmi.GetDWORDValue($hklm, $OfcService_64_Key, $RCS_Key)
        $RCS_Val = $RCS_Val.uvalue
		# Check for Trendmicro WFBS version on a 64 bit machine TmFilter_Ver=9.850.1008
		# Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
		$Tm_PatternDate = $wmi.GetStringValue($hklm, $OfcService_64_Key, $Tm_PatternDate_Key)
		$Tm_PatternDate = $Tm_PatternDate.svalue
		}
	Else {
		# Check for Trendmicro WFBS version on a 32 bit machine TmListen_Ver=19.0.3273          
		$Client_Version = $wmi.GetStringValue($hklm, $OfcService_32_Key, $Client_Version_Key)
		$Client_Version = $Client_Version.svalue
		$Server_Version = $wmi.GetStringValue($hklm, $OfcService_32_Key, $Server_Version_Key)
		$Server_Version = $Server_Version.svalue
		$UpdateFrom = $wmi.GetStringValue($hklm, $OfcService_32_Key, $UpdateFrom_Key)
		$UpdateFrom = $UpdateFrom.svalue		# Check for Trendmicro WFBS version on a 32 bit machine TmFilter_Ver=9.850.1008
        # RCS_Val = 202 for (RDS/Citrix Server)
        $RCS_Val = $wmi.GetDWORDValue($hklm, $OfcService_32_Key, $RCS_Key)
        $RCS_Val = $RCS_Val.uvalue
		# Check for Trendmicro WFBS version on a 32 bit machine PatternDate=20160226
		$Tm_PatternDate = $wmi.GetStringValue($hklm, $OfcService_32_Key, $Tm_PatternDate_Key)
		$Tm_PatternDate = $Tm_PatternDate.svalue
		}
    $MiniFilter_Val = $wmi.GetDWORDValue($hklm, $OfcServices_Key, $EnableMiniFilter_Key)
    $MiniFIlter_Val = $MiniFilter_Val.uvalue

	if ($Client_Version -eq "") {
        $Tm_AV_Ok=$false
        $ReturnMsg = "TM WFBS Version unknown"
        }
    else {
        if ([int]$Server_Version.length -eq 0 -AND [int]$Client_Version.length -gt 0 ) {
            $Tm_AV_Ok=$true
            $TM_WFBS_Services = $true
            $ReturnMsg = "WFBS Services Client - Version " + $Client_Version
            #$ReturnValue += New-SVTestResult "Antivirus installed" $ReturnMsg $true
            }
        else {
            if ([int]$Server_Version.length -gt 0 -AND [int]$Client_Version.length -gt 0 ) {
                $Tm_AV_Ok=$true
                $TM_WFBS_Services = $false
                $ReturnMsg = "WFBS Client/Server(" + $UpdateFrom.split("://")[3] + ") - Version " + $Client_Version + " / " + $Server_Version
                #$ReturnValue += New-SVTestResult "Antivirus installed" $ReturnMsg $true
                }
            }
          
            $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

            $PatternYear=$Tm_PatternDate.Substring(0,4)
            $PatternMonth=$Tm_PatternDate.Substring(4,2)
            if ([int]$PatternMonth -gt 12) {
                $PatternMonth=$Tm_PatternDate.Substring(6,2)
                $PatternDay=$Tm_PatternDate.Substring(4,2)
                }
            else {
                $PatternDay=$Tm_PatternDate.Substring(6,2)
                }
            $PatternDate2=$PatternYear+"/"+$PatternMonth+"/"+$PatternDay

            $PatternDate=(get-date "$PatternDate2").Ticks
            #$TodayDate=(get-date).TicksM

            $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2

            if ($PatternDate -gt $TodayMinus7Days) {
                $AV_Ok=$true                
                $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            else {
                $AV_Ok=$false
                $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            
            ######################################
            $RCS_CpmConfig = 0
            try {
                $RDS_Server = Invoke-Command -ComputerName $comp -scriptblock {Import-Module ServerManager; Get-WindowsFeature RDS-RD-Server} -ErrorAction SilentlyContinue
                #If get-windowsfeature RDS-Server gives an error, do following instruction on remote server Import-Module ServerManager
                #$RDS_Server=Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" | select -ExpandProperty TerminalServerMode
                }
            catch {}
            if ($RDS_Server.Installed) {
                if ($TM_WFBS_Services) {
                    try {
                        $RCS_CpmConfig_Val = Get-Content -Path "C:\Program Files (x86)\Trend Micro\Client Server Security Agent\HostedAgent\CPM\CpmConfig.ini" | Where-Object { $_ -match 'RCS =' }
                        $RCS_CpmConfig_Val = Invoke-Command -ComputerName $comp -scriptblock {Get-Content -Path "C:\Program Files (x86)\Trend Micro\Client Server Security Agent\HostedAgent\CPM\CpmConfig.ini" | Where-Object { $_ -match 'RCS =' } } -ErrorAction SilentlyContinue
                        }
                    catch {}
                    if ($RCS_CpmConfig_Val) {
                        $RCS_CpmConfig = $RCS_CpmConfig_Val.split("=")[1].trim()
                        #echo $RCS_CpmConfig
                        }                    
                    if ($RCS_Val -eq 202) {
                        $ReturnMsg = "WFBS Services Client - RDS/CTX -> RCS: " + $RCS_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = "WFBS Services Client - RDS/CTX -> RCS: " + $RCS_Val + " (NOK)"
                        }
                    if ($MiniFilter_Val -eq 1) {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (NOK)"
                        }
                    if ($RCS_CpmConfig -eq 1) {
                        $ReturnMsg = $ReturnMsg + " - RCS Services: " + $RCS_CpmConfig + " (OK)"
                        }
                    else {
                        $ReturnMsg = $ReturnMsg + " - RCS Services: " + $RCS_CpmConfig + " (NOK)"
                        }
                    }                    
                else {
                    if ($RCS_Val -eq 202) {
                        $ReturnMsg = "WFBS Client/Server(" + $UpdateFrom.split("://")[3] + ") - RDS/CTX -> RCS: " + $RCS_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = "WFBS Client/Server(" + $UpdateFrom.split("://")[3] + ") - RDS/CTX -> RCS: " + $RCS_Val + " (NOK)"
                        }
                    if ($MiniFilter_Val -eq 1) {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (NOK)"
                        }
                    }
                
                if ($TM_WFBS_Services) {
                    if ( ($MiniFilter_Val -eq 0) -or ($RCS_Val -eq 101) -or ($RCS_CpmConfig -eq 0) ) {
                        $AV_Ok=$false
                        }                
                    }
                else {
                    if ( ($MiniFilter_Val -eq 0) -or ($RCS_Val -eq 101) ) {
                        $AV_Ok=$false
                        }
                    }
                                
                $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            ######################################

        }
    Return New-SVTest "Antivirus" $ReturnValue
}
