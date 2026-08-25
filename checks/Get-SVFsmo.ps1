function Get-SVFSMO() {
    $ReturnValue = @()
    $fsmo = @()

    $temp_fsmo = netdom /query fsmo
    foreach ($item in $temp_fsmo) {
        if ($item -notlike "The Command completed successfully*") {
            if ($item -ne "") {
                #$fsmo += $item
                $ReturnValue += New-SVTestResult "FSMO Roles" $item $true
                }
            }
        }

return New-SVTest "FSMO Roles" $ReturnValue
}
