function Get-SVAntiVirus($comp) {

    $AV_Installed = $false
    $ReturnValue = @()

    $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -ErrorAction Continue    
    foreach ($proc in $processes) {
        switch ($proc.name) 
            { 
            "SophosFileScanner.exe" { $ReturnValue = Get-SVSophos $comp ;$AV_Installed = $true}
            "epconsole.exe" { $ReturnValue = Get-SVAV_NABLEAV $comp ;$AV_Installed = $true}
            "NTRTScan.exe" { $ReturnValue = Get-SVTm $comp ;$AV_Installed = $true}
            "mcshield.exe" { $ReturnValue = Get-SVMcAfee $comp ;$AV_Installed = $true}
            "ccSvcHst.exe" { $ReturnValue = Get-SVSep $comp ;$AV_Installed = $true}
            "WRSA.exe" { $ReturnValue = Get-SVWrsa $comp ;$AV_Installed = $true}
            "ekrn.exe" { $ReturnValue = Get-SVEset $comp ;$AV_Installed = $true}
            "cpda.exe" { $ReturnValue = Get-SVEpp $comp ;$AV_Installed = $true}
            "fmon.exe" { $ReturnValue = Get-SVFortiClient $comp ;$AV_Installed = $true}
            "MsSense.exe" {$ReturnValue = Get-SVCheckWindowsDefenderAtp $comp ;$AV_Installed = $true}
            }
        }

    if (-NOT $AV_Installed) {
        foreach ($proc in $processes) {
            if ($proc.name -eq "MsMpEng.exe") { 
                $ReturnValue = Get-SVMsse $comp
                $AV_Installed = $true
                }
            else {
                $ReturnValue = Get-SVNoInstalled $comp
                }
            }
        }
    Return New-SVTest "Antivirus" $ReturnValue.testresult
}
