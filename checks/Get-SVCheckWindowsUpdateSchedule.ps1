function Get-SVCheckWindowsUpdateSchedule($server){
    $AutoUpdateDays=@{0="Every Day"; 1="Every Sunday"; 2="Every Monday"; 3="Every Tuesday"; 4="Every Wednesday"; 5="Every Thursday"; 6="Every Friday"; 7="Every Saturday"}
    $ReturnValue = @()

    try {
        $hklm = 2147483650
        $policyKey = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\"
        $currentKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\"
        $wmi = Get-WmiObject -List "StdRegProv" -Namespace "root\default" -ComputerName $server -ErrorAction Stop

        $autoUpdateOption = ($wmi.GetDWORDValue($hklm, $policyKey, "AUOptions")).UValue
        $scheduledDay = ($wmi.GetDWORDValue($hklm, $policyKey, "ScheduledInstallDay")).UValue
        $scheduledTime = ($wmi.GetDWORDValue($hklm, $policyKey, "ScheduledInstallTime")).UValue

        if ($null -eq $scheduledDay) {
            $scheduledDay = ($wmi.GetDWORDValue($hklm, $currentKey, "ScheduledInstallDay")).UValue
        }
        if ($null -eq $scheduledTime) {
            $scheduledTime = ($wmi.GetDWORDValue($hklm, $currentKey, "ScheduledInstallTime")).UValue
        }

        if ([int]$autoUpdateOption -eq 4 -and $null -ne $scheduledDay -and $null -ne $scheduledTime) {
            $ReturnValue += New-SVTestResult "Automatic Updates Schedule" ("" + $AutoUpdateDays[[int]$scheduledDay] + " at " + $scheduledTime + ":00") $true
        }
        else {
            $ReturnValue += New-SVTestResult "Automatic Updates Schedule" "Geen reboot door updates" $true
        }
    }
    catch {
        $ReturnValue += New-SVTestResult "Automatic Updates Schedule" "De informatie kan niet worden uitgelezen" $false
    }

	return New-SVTest "Automatic Updates Schedule" $ReturnValue

}
