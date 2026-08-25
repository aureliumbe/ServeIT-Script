function Get-SVPDC() {
    $ReturnValue = @()

    $temp_pdc = netdom /query pdc
    foreach ($item in $temp_pdc) {
        if ($item -notlike "Primary domain controller for the domain*") {
            if ($item -ne "") {
                if ($item -notlike "The Command completed successfully*") {
                    $ReturnValue += New-SVTestResult "Primary Domain Controller" $item $true
                    }
                }
            }
        }
return New-SVTest "Primary Domain Controller" $ReturnValue
}
