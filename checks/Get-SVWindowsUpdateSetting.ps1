function Get-SVWindowsUpdateSetting($server){
    $AutoUpdateDays=@{0="Every Day"; 1="Every Sunday"; 2="Every Monday"; 3="Every Tuesday"; 4="Every Wednesday";5="Every Thursday"; 6="Every Friday"; 7="EverySaturday"}
    $ReturnValue = @()
	
    $wusettings = ([activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.AutoUpdate",$server))).Settings
    
    if ($wusettings.NotificationLevel -eq $null) {
        $ReturnValue += New-SVTestResult "Windows Update" "De informatie kan niet worden uitgelezen" $false
    }
    elseif ([int]$wusettings.NotificationLevel -eq 4) {
        $ReturnValue += New-SVTestResult "Windows Update" ("" + $autoupdatedays[$wusettings.ScheduledInstallationDay] + " at " + $wusettings.ScheduledInstallationTime + ":00")  $true
    } 
    else {
        $ReturnValue += New-SVTestResult "Windows Update" "Geen reboot door updates" $true
    }
	return New-SVTest "Windows Update" $ReturnValue

}
