function Get-SVCheckWindowsUpdateSettings($server) {

    $hklm = 2147483650
    $key = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\"
    $key1 = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\"
    $key3 = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\"

    $UseWUServer = "UseWUServer"
    $WUServer = "WUServer"
    $NoAutoUpdate = "NoAutoUpdate"
    $AUOptions = "AUOptions"
    $ScheduledInstallDay = "ScheduledInstallDay"
    $ScheduledInstallTime = "ScheduledInstallTime"

    $ReturnValue = @()
    $ReturnMsg = ""
  
    $OS_Version = Get-SVOSVersion $server

    # First check if there is an WIndows Update Policy, check the regkey: "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer"
    # If positive, check the regkey: "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer" en "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUStatusServer"
    # If positive, use the WSUS update settings, if negative, use the "internet settings"

    # Check Windows Update Configuration
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $server
  
    $Comp_UseWUServer = $wmi.GetDWORDValue($hklm, $Key1, $UseWUServer)
    $Comp_UseWUServer = $Comp_UseWUServer.UValue
   
    $Comp_NoAutoUpdate = $wmi.GetDWORDValue($hklm, $Key1, $NoAutoUpdate)
    $Comp_NoAutoUpdate = $Comp_NoAutoUpdate.UValue

    if ([int]$OS_Version -gt 60) {
        $Comp_WUServer = $wmi.GetStringValue($hklm, $Key, $WUServer)
        $Comp_WUServer = $Comp_WUServer.sValue
        if ($Comp_WUServer.length -ne "0") {
            $Comp_WUServer = $Comp_WUServer.split("//")[2]
            }
        #else {
            $Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key1, $AUOptions)
            $Comp_AUOptions = $Comp_AUOptions.UValue

            $Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallDay)
            $Comp_ScheduledInstallDay = $Comp_ScheduledInstallDay.UValue

            $Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallTime)
            $Comp_ScheduledInstallTime = $Comp_ScheduledInstallTime.UValue
            $Comp_ScheduledInstallTime = "{0,2}" -f $Comp_ScheduledInstallTime  

            if ($Comp_AUOptions -ne $null) {
                Switch ($Comp_AUOptions) 
                    {    
                    "1" {$ReturnMsg = "Automatic updates has been Disabled"}
                    "2" {$ReturnMsg = "Notify  for  Download  &   Installation"}
                    "3" {$ReturnMsg = "Auto Download & Notify for Installation"}
                    "4" {$ReturnMsg = "Auto Download & Scheduled  Installation"}
                    "5" {$ReturnMsg = "Automatic updates enabled but allow local admin to choose settings"}
                    }
                }

            if ($Comp_ScheduledInstallDay -ne $null) {
                Switch ($Comp_ScheduledInstallDay)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + ", Everyday "}
                    "1" {$ReturnMsg = $ReturnMsg + ", Sunday   "}
                    "2" {$ReturnMsg = $ReturnMsg + ", Monday   "}
                    "3" {$ReturnMsg = $ReturnMsg + ", Tuesday  "}
                    "4" {$ReturnMsg = $ReturnMsg + ", Wednesday"}
                    "5" {$ReturnMsg = $ReturnMsg + ", Thursday "}
                    "6" {$ReturnMsg = $ReturnMsg + ", Friday   "}
                    "7" {$ReturnMsg = $ReturnMsg + ", Saturday "}    
                    }
                }

            If ($Comp_ScheduledInstallTime.trim().length -ne 0) {
                $ReturnMsg = $ReturnMsg + " at:" + $Comp_ScheduledInstallTime+"h"
                }
    
            if ($Comp_UseWUServer -ne $null) {
                Switch ($Comp_UseWUServer)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + " (Update from Microsoft)"}
                    "1" {if ($Comp_WUServer -ne $null) {
                            $ReturnMsg = $ReturnMsg + " (Update from WSUS server:"+ $comp_WUServer+")"
                            }
                        }
                    }
                }

            #echo $ReturnMsg
            $ReturnValue += New-SVTestResult "Windows Update Settings" $ReturnMsg $true
        }
    
    elseIf ($Comp_NoAutoUpdate -eq $null -and $Comp_UseWUServer -eq $null) {
        #$Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key3, $AUOptions)
        $Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key1, $AUOptions)
        $Comp_AUOptions = $Comp_AUOptions.UValue

        $Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key3, $ScheduledInstallDay)
        #$Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallDay)
        $Comp_ScheduledInstallDay = $Comp_ScheduledInstallDay.UValue

        $Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key3, $ScheduledInstallTime)
        #$Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallTime)
        $Comp_ScheduledInstallTime = $Comp_ScheduledInstallTime.UValue
        $Comp_ScheduledInstallTime = "{0,2}" -f $Comp_ScheduledInstallTime  

        if ($Comp_AUOptions -ne $null) {
            Switch ($Comp_AUOptions) 
                {    
                "0" {$ReturnMsg = "Automatic updates enabled and downloaded updates will be installed immediately"}
                "1" {$ReturnMsg = "Automatic updates disabled, however users can manually initiate update"}
                "2" {$ReturnMsg = "Check for updates but do not download them until user says so"}
                "3" {$ReturnMsg = "Download the updates but do not install"}
                "4" {$ReturnMsg = "Automatic updates enabled but allow local admin to choose settings"}
                }
            }

        if ($Comp_ScheduledInstallDay -ne $null) {
            Switch ($Comp_ScheduledInstallDay)
                {
                "0" {$ReturnMsg = $ReturnMsg + ", Everyday "}
                "1" {$ReturnMsg = $ReturnMsg + ", Sunday   "}
                "2" {$ReturnMsg = $ReturnMsg + ", Monday   "}
                "3" {$ReturnMsg = $ReturnMsg + ", Tuesday  "}
                "4" {$ReturnMsg = $ReturnMsg + ", Wednesday"}
                "5" {$ReturnMsg = $ReturnMsg + ", Thursday "}
                "6" {$ReturnMsg = $ReturnMsg + ", Friday   "}
                "7" {$ReturnMsg = $ReturnMsg + ", Saterday "}    
                }
            }

        If ($Comp_ScheduledInstallTime.trim().length -ne 0) {
            $ReturnMsg = $ReturnMsg + " at:" + $Comp_ScheduledInstallTime+"h"
            }
     
        $ReturnValue += New-SVTestResult "Windows Update Settings" $ReturnMsg $true
        # End of If statement
        }
        else {
            $Comp_WUServer = $wmi.GetStringValue($hklm, $Key, $WUServer)
            $Comp_WUServer = $Comp_WUServer.sValue
            if ($Comp_WUServer.length -ne "0") {
                $Comp_WUServer = $Comp_WUServer.split("//")[2]
                }
            #else {
            $Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key1, $AUOptions)
            $Comp_AUOptions = $Comp_AUOptions.UValue

            $Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallDay)
            $Comp_ScheduledInstallDay = $Comp_ScheduledInstallDay.UValue

            $Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallTime)
            $Comp_ScheduledInstallTime = $Comp_ScheduledInstallTime.UValue
            $Comp_ScheduledInstallTime = "{0,2}" -f $Comp_ScheduledInstallTime  

            If ($Comp_NoAutoUpdate -ne $null) {
                Switch ($Comp_NoAutoUpdate)
                    {
                    "0" {$WU_Ok=$true; $ReturnMsg =  "Auto Update"}
                    "1" {$WU_Ok=$false; $ReturnMsg = "No Auto Update"}
                    }
                }
    
            if ($Comp_UseWUServer -ne $null) {
                Switch ($Comp_UseWUServer)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + " from Microsoft"}
                    "1" {$ReturnMsg = $ReturnMsg + " from WSUS server"}
                    }
                }

            if ($Comp_WUServer -ne $null) {
                $ReturnMsg = $ReturnMsg + ":" + $comp_WUServer
                }

            if ($Comp_AUOptions -ne $null) {
                Switch ($Comp_AUOptions) 
                    {    
                    "1" {$ReturnMsg = $ReturnMsg + ", Automatic updates has been Disabled"}
                    "2" {$ReturnMsg = $ReturnMsg + ", Notify for Download & Installation"}
                    "3" {$ReturnMsg = $ReturnMsg + ", Auto Download & Notify for Installation"}
                    "4" {$ReturnMsg = $ReturnMsg + ", Auto Download & Scheduled Installation"}
                    "5" {$ReturnMsg = $ReturnMsg + ", Automatic updates enabled but allow local admin to choose settings"}
                    }
                }

            if ($Comp_ScheduledInstallDay -ne $null) {
                Switch ($Comp_ScheduledInstallDay)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + ", Everyday "}
                    "1" {$ReturnMsg = $ReturnMsg + ", Sunday   "}
                    "2" {$ReturnMsg = $ReturnMsg + ", Monday   "}
                    "3" {$ReturnMsg = $ReturnMsg + ", Tuesday  "}
                    "4" {$ReturnMsg = $ReturnMsg + ", Wednesday"}
                    "5" {$ReturnMsg = $ReturnMsg + ", Thursday "}
                    "6" {$ReturnMsg = $ReturnMsg + ", Friday   "}
                    "7" {$ReturnMsg = $ReturnMsg + ", Saterday "}    
                    }
                }

            If ($Comp_ScheduledInstallTime.trim().length -ne 0) {
                $ReturnMsg = $ReturnMsg + " at:" + $Comp_ScheduledInstallTime+"h"
                }
            echo $ReturnMsg
            $ReturnValue += New-SVTestResult "Windows Update Settings" $ReturnMsg $true
            #}
        }

    return New-SVTest "Windows Update Settings" $ReturnValue
    }
