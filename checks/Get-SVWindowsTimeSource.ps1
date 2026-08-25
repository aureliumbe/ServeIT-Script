function Get-SVWindowsTimeSource($server){
    $ReturnValue = @()
    $PDCtimeSyncSource = "ntp.belbone.be,0x1"
    $PDC=Get-ADDomain | Select-Object PDCEmulator

    $TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { w32tm /query /source }

    if ($server -eq $PDC.PDCEmulator.split(".")[0] ) {      
        If ( $TimeSource.split(",0x1") -contains "ntp.belbone.be" ) {
            $ReturnValue += New-SVTestResult "TimeSource" $TimeSource $true
            }
        else {
            $ReturnValue += New-SVTestResult "TimeSource" $TimeSource $false
            }
        }
    else {
        $ReturnValue += New-SVTestResult "TimeSource" $TimeSource ($PDC.PDCEmulator -contains $TimeSource.Trim())
        }

    return New-SVTest "Timesource" $ReturnValue
}
